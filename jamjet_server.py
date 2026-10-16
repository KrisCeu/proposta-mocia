import json
import sys
import time
from datetime import datetime
from pathlib import Path
from mcp.server.fastmcp import FastMCP
import yaml

# Âncora no próprio diretório do script
BASE_DIR = Path(__file__).resolve().parent
POLICY_PATH = BASE_DIR / "policy.yaml"
AUDIT_LOG_PATH = BASE_DIR / "audit_trail.jsonl"

mcp = FastMCP("jamjet-action-control")


def carregar_politica() -> dict:
  try:
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
      return yaml.safe_load(f)
  except Exception:
    return {"budget_limits": {"max_transaction_value": 200.00}, "rules": []}


def registrar_trilha_auditoria(
    tool_name: str, args: dict, decisao: dict
) -> None:
  entrada = {
      "timestamp": datetime.utcnow().isoformat() + "Z",
      "tool_intercepted": tool_name,
      "arguments": args,
      "decision": decisao,
  }
  with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
    f.write(json.dumps(entrada, ensure_ascii=False) + "\n")


@mcp.tool()
def executar_pagamento(valor: float, moeda: str, destinatario: str) -> str:
  """Executa um pagamento bancário interdomínio após avaliação do JamJet."""
  t_inicio = time.perf_counter()
  politica = carregar_politica()
  limite_teto = politica.get("budget_limits", {}).get(
      "max_transaction_value", 200.00
  )

  if valor <= limite_teto:
    status = "APPROVED"
    motivo = (
        f"Transação dentro do limite orçamentário configurado (R$"
        f" {limite_teto:.2f})."
    )
    payload_resposta = {
        "resultado": "SUCESSO",
        "id_transacao": f"tx_{int(time.time())}",
        "valor_processado": valor,
        "moeda": moeda,
        "favorecido": destinatario,
        "provenance": {
            "produced_by": "delegate:qwen2.5-3b",
            "verification": {"performed": True, "status": "passed"},
        },
    }
  else:
    status = "REQUIRE_APPROVAL"
    motivo = (
        f"Alerta HITL: Valor R$ {valor:.2f} excede o teto orçamentário de R$"
        f" {limite_teto:.2f}."
    )
    payload_resposta = {
        "resultado": "PAUSADO_PARA_APROVACAO",
        "aviso": motivo,
        "checkpoint": f"chk_{int(time.time())}",
    }

  latencia_ms = (time.perf_counter() - t_inicio) * 1000
  decisao = {
      "status": status,
      "reason": motivo,
      "eval_latency_ms": round(latencia_ms, 3),
  }

  registrar_trilha_auditoria(
      "executar_pagamento",
      {"valor": valor, "moeda": moeda, "destinatario": destinatario},
      decisao,
  )
  return json.dumps(payload_resposta, ensure_ascii=False)


@mcp.tool()
def executar_comando_sistema(comando: str) -> str:
  """Simulação de comando de terminal/OS para validação de bloqueio ativo."""
  t_inicio = time.perf_counter()
  decisao = {
      "status": "DENIED",
      "reason": (
          "Ação bloqueada: chamadas de terminal/OS são proibidas pelo"
          " policy.yaml."
      ),
      "eval_latency_ms": round((time.perf_counter() - t_inicio) * 1000, 3),
  }
  registrar_trilha_auditoria(
      "executar_comando_sistema", {"comando": comando}, decisao
  )
  return json.dumps(
      {"resultado": "BLOQUEIO_DETERMINISTICO", "motivo": decisao["reason"]},
      ensure_ascii=False,
  )


if __name__ == "__main__":
  print("Iniciando JamJet Action-Control Plane...", file=sys.stderr)
  mcp.run(transport="stdio")
