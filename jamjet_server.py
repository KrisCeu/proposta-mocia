import json
import os
import time
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify
import yaml

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
POLICY_PATH = BASE_DIR / "policy.yaml"
AUDIT_LOG_PATH = BASE_DIR / "audit_trail.jsonl"


def carregar_politica() -> dict:
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return {"budget_limits": {"max_transaction_value": 200.00}, "rules": []}


def registrar_trilha_auditoria(tool_name: str, args: dict, decisao: dict) -> None:
    entrada = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tool_intercepted": tool_name,
        "arguments": args,
        "decision": decisao,
    }
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entrada, ensure_ascii=False) + "\n")


def auditar_com_jamjet(policy_dict, frame_ldp, decisao_llm):
    """
    Mesma lógica que estava em agente1_servidor.py, agora como serviço.
    - Checagem 1: integridade (amount_llm vs amount_ldp, target_llm vs target_ldp)
    - Checagem 2: policy engine (rules do policy.yaml)
    """
    tool_llm = decisao_llm.get("tool")
    action_llm = decisao_llm.get("action")
    amount_llm = float(decisao_llm.get("amount", 0))
    amount_ldp = float(frame_ldp.get("amount", 0))
    target_llm = decisao_llm.get("target")
    target_ldp = frame_ldp.get("target")

    if amount_llm != amount_ldp or target_llm != target_ldp:
        return {
            "jamjet_action": "deny",
            "divergencia_detectada": True,
            "motivo_jamjet": (
                f"BLOQUEIO DE INTEGRIDADE: O pedido LDP original era "
                f"(R$ {amount_ldp} para '{target_ldp}'), mas a LLM tentou executar "
                f"(R$ {amount_llm} para '{target_llm}')."
            ),
        }

    acao_esperada = "deny"
    for regra in policy_dict.get("rules", []):
        if regra.get("tool") == tool_llm:
            has_max = "max_amount" in regra
            has_min = "min_amount" in regra
            if has_max and amount_llm <= float(regra["max_amount"]):
                acao_esperada = regra["action"]
                break
            elif has_min and amount_llm >= float(regra["min_amount"]):
                acao_esperada = regra["action"]
                break
            elif not has_max and not has_min:
                acao_esperada = regra["action"]
                break

    divergencia = (action_llm != acao_esperada)
    motivo = (
        f"Decisão da LLM ('{action_llm}') confirmada pelo policy.yaml."
        if not divergencia else
        f"CONTENÇÃO JAMJET: A LLM tentou '{action_llm}', mas a regra exige '{acao_esperada}'."
    )

    return {
        "jamjet_action": acao_esperada,
        "divergencia_detectada": divergencia,
        "motivo_jamjet": motivo,
    }


@app.route("/audit", methods=["POST"])
def audit_tool_call():
    t_inicio = time.perf_counter()
    dados = request.json

    frame_ldp = dados["frame_ldp"]
    decisao_llm = dados["decisao_llm"]

    policy_dict = carregar_politica()
    resultado = auditar_com_jamjet(policy_dict, frame_ldp, decisao_llm)

    latencia_ms = (time.perf_counter() - t_inicio) * 1000

    registrar_trilha_auditoria(
        tool_name=decisao_llm.get("tool", "desconhecida"),
        args={
            "amount_ldp": frame_ldp.get("amount"),
            "target_ldp": frame_ldp.get("target"),
            "amount_llm": decisao_llm.get("amount"),
            "target_llm": decisao_llm.get("target"),
            "action_llm": decisao_llm.get("action"),
        },
        decisao={
            "jamjet_action": resultado["jamjet_action"],
            "divergencia_detectada": resultado["divergencia_detectada"],
            "motivo_jamjet": resultado["motivo_jamjet"],
            "eval_latency_ms": round(latencia_ms, 3),
        },
    )

    return jsonify({
        "jamjet_action": resultado["jamjet_action"],
        "divergencia_detectada": resultado["divergencia_detectada"],
        "motivo_jamjet": resultado["motivo_jamjet"],
        "eval_latency_ms": round(latencia_ms, 3),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    PORTA = int(os.getenv("PORTA_JAMJET", "8004"))
    print(f"JamJet Action-Control Service ativo na porta {PORTA}...", flush=True)
    app.run(host="0.0.0.0", port=PORTA)