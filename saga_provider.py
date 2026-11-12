from flask import Flask, request, jsonify
import uuid
import threading

app = Flask(__name__)

# Simulando o banco de dados do Provider
CPAs = {
    "ans://v1.0.0.financeiro.mocia.internal": ["ans://v1.0.0.compras.mocia.internal"],
    "ans://v1.0.0.pagamentos-rapidos.internal": []
}
OTKS = {
    "ans://v1.0.0.financeiro.mocia.internal": [f"OTK-{i}" for i in range(1, 1000)]
}

# ─── Fix S-2/S-4: OTKs emitidas e ainda não consumidas ───
# Quando o AHP consome via /otk-verify, a OTK é removida daqui.
# - Se OTK não está aqui → nunca emitida OU já consumida → 403 (cobre S-4 e S-2).
OTKS_ATIVAS = set()
_otk_lock = threading.Lock()


@app.route("/contact-request", methods=["POST"])
def contact_request():
    dados = request.json
    destino = dados["destino"]
    origem = dados["origem"]

    # 1. Verifica a CPA
    if origem not in CPAs.get(destino, []):
        return jsonify({"erro": "CPA bloqueou a conexão"}), 403

    # 2. Consome uma OTK (se houver)
    if not OTKS.get(destino):
        return jsonify({"erro": "Sem OTK disponível"}), 403

    with _otk_lock:
        otk_entregue = OTKS[destino].pop(0)
        OTKS_ATIVAS.add(otk_entregue)

    return jsonify({"otk": otk_entregue, "provider_id": "SAGA_PROV_1"})


@app.route("/otk-verify", methods=["POST"])
def otk_verify():
    """Consome uma OTK. Retorna valid=True apenas no primeiro uso.

    Chamado pelo AHP para validar a OTK recebida do solicitante.
    - OTK nunca emitida pelo provider → 403 (fix S-4)
    - OTK já consumida por um AHP anterior → 403 (fix S-2)
    """
    dados = request.json or {}
    otk = dados.get("otk")
    if not otk:
        return jsonify({"valid": False, "erro": "OTK ausente"}), 400

    with _otk_lock:
        if otk not in OTKS_ATIVAS:
            return jsonify({"valid": False, "erro": "OTK inválida ou já consumida"}), 403
        OTKS_ATIVAS.discard(otk)

    return jsonify({"valid": True, "otk": otk})


if __name__ == "__main__":
    print("SAGA Provider ativo na porta 8003...", flush=True)
    app.run(host="0.0.0.0", port=8003)