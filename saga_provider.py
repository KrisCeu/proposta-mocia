from flask import Flask, request, jsonify
import uuid

app = Flask(__name__)

# Simulando o banco de dados do Provider
CPAs = {
    "ans://v1.0.0.financeiro.mocia.internal": ["ans://v1.0.0.compras.mocia.internal"], # Só aceita compras
    "ans://v1.0.0.pagamentos-rapidos.internal": [] # Não aceita ninguém
}
OTKS = {
    "ans://v1.0.0.financeiro.mocia.internal": ["OTK-123", "OTK-456"] # Chaves descartáveis
}

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
        
    otk_entregue = OTKS[destino].pop(0)
    return jsonify({"otk": otk_entregue, "provider_id": "SAGA_PROV_1"})

if __name__ == "__main__":
    print("SAGA Provider ativo na porta 8003...", flush=True)
    app.run(host="0.0.0.0", port=8003)