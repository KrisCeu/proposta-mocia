import json
import os
import time
import unicodedata
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify
import yaml

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
POLICY_PATH = BASE_DIR / "policy.yaml"
ALLOWLIST_PATH = BASE_DIR / "allowlist.yaml"
AUDIT_LOG_PATH = BASE_DIR / "audit_trail.jsonl"


# ═══════════════════════════════════════════════════════════════════
# Carregamento — policy.yaml (LLM lê) vs allowlist.yaml (só JamJet lê)
# ═══════════════════════════════════════════════════════════════════

def _load_yaml(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def carregar_politica() -> dict:
    """Lê policy.yaml. Este é o mesmo conteúdo que a LLM recebe no prompt."""
    policy = _load_yaml(POLICY_PATH)
    if not policy:
        return {"budget_limits": {"max_transaction_value": 200.00}, "rules": []}
    return policy


def carregar_allowlist() -> dict:
    """Lê allowlist.yaml. Exclusivo do JamJet — não vai para o prompt da LLM."""
    return _load_yaml(ALLOWLIST_PATH)


def registrar_trilha_auditoria(tool_name: str, args: dict, decisao: dict) -> None:
    entrada = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tool_intercepted": tool_name,
        "arguments": args,
        "decision": decisao,
    }
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entrada, ensure_ascii=False) + "\n")


# ═══════════════════════════════════════════════════════════════════
# Helpers de normalização e comparação
# ═══════════════════════════════════════════════════════════════════

def _normalizar(s: str) -> str:
    if not isinstance(s, str):
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = "".join(c for c in s if unicodedata.category(c) not in ("Cf", "Cc"))
    return s.strip().lower()


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ═══════════════════════════════════════════════════════════════════
# Checagens que usam allowlist (só JamJet conhece)
# ═══════════════════════════════════════════════════════════════════

def _checar_recipient(target: str, allowlist_dict: dict):
    cfg = allowlist_dict.get("recipients", {})
    if not cfg:
        return None

    trusted = cfg.get("trusted", [])
    on_unknown = cfg.get("on_unknown", "require_approval_for")
    do_normalize = cfg.get("normalize", True)
    on_typosquat = allowlist_dict.get("security_controls", {}).get(
        "on_recipient_typosquat", "deny"
    )

    if do_normalize:
        target_cmp = _normalizar(target)
        trusted_norm = {_normalizar(t): t for t in trusted}
    else:
        target_cmp = target
        trusted_norm = {t: t for t in trusted}

    if target_cmp in trusted_norm:
        return None

    if on_typosquat in ("deny", "require_approval_for"):
        for t_norm, t_orig in trusted_norm.items():
            if _levenshtein(target_cmp, t_norm) <= 2:
                return {
                    "jamjet_action": on_typosquat,
                    "divergencia_detectada": False,
                    "motivo_jamjet": (
                        f"TYPOQUAT SUSPEITO: '{target}' é muito similar a "
                        f"destinatário confiável '{t_orig}' (distância ≤ 2)."
                    ),
                }

    if on_unknown == "deny":
        return {
            "jamjet_action": "deny",
            "divergencia_detectada": False,
            "motivo_jamjet": (
                f"DESTINATÁRIO NÃO AUTORIZADO: '{target}' não está na allowlist. "
                f"Bloqueio total (on_unknown=deny)."
            ),
        }
    return {
        "jamjet_action": "require_approval_for",
        "divergencia_detectada": False,
        "motivo_jamjet": (
            f"DESTINATÁRIO DESCONHECIDO: '{target}' não está na allowlist. "
            f"Requer aprovação humana (on_unknown=require_approval_for)."
        ),
    }


def _checar_consistencia_notes_target(target_llm: str, frame_ldp: dict, allowlist_dict: dict):
    cfg = allowlist_dict.get("recipients", {})
    trusted = cfg.get("trusted", [])
    if not trusted:
        return None

    on_inconsistency = allowlist_dict.get("security_controls", {}).get(
        "on_recipient_inconsistency", "log"
    )
    if on_inconsistency == "log":
        return None

    notes = frame_ldp.get("notes", "") or ""
    notes_norm = _normalizar(notes)
    target_norm = _normalizar(target_llm)

    for t in trusted:
        t_norm = _normalizar(t)
        if t_norm in notes_norm and t_norm != target_norm:
            return {
                "jamjet_action": on_inconsistency,
                "divergencia_detectada": False,
                "motivo_jamjet": (
                    f"INCONSISTÊNCIA NOTES-TARGET: notes menciona '{t}', "
                    f"mas target é '{target_llm}'."
                ),
            }
    return None


# ═══════════════════════════════════════════════════════════════════
# Função principal de auditoria
# ═══════════════════════════════════════════════════════════════════

def auditar_com_jamjet(policy_dict, allowlist_dict, frame_ldp, decisao_llm):
    tool_llm = decisao_llm.get("tool")
    action_llm = decisao_llm.get("action")
    amount_llm = float(decisao_llm.get("amount", 0))
    amount_ldp = float(frame_ldp.get("amount", 0))
    target_llm = decisao_llm.get("target")
    target_ldp = frame_ldp.get("target")
    tool_ldp = frame_ldp.get("requested_tool")

    # ─── Camada 0: sinal ───
    if amount_llm < 0 or amount_ldp < 0:
        return {
            "jamjet_action": "deny",
            "divergencia_detectada": True,
            "motivo_jamjet": (
                f"ENTRADA INVÁLIDA: valor negativo "
                f"(LLM={amount_llm}, LDP={amount_ldp})."
            ),
        }

    # ─── Camada 1: integridade ───
    if amount_llm != amount_ldp or target_llm != target_ldp or tool_llm != tool_ldp:
        return {
            "jamjet_action": "deny",
            "divergencia_detectada": True,
            "motivo_jamjet": (
                f"BLOQUEIO DE INTEGRIDADE: LDP=(tool={tool_ldp}, "
                f"R$ {amount_ldp} para '{target_ldp}') vs "
                f"LLM=(tool={tool_llm}, R$ {amount_llm} para '{target_llm}')."
            ),
        }

    # ─── Camada 2: allowlist (só JamJet conhece) ───
    check_recipient = _checar_recipient(target_llm, allowlist_dict)
    if check_recipient is not None:
        return check_recipient

    # ─── Camada 3: consistência notes↔target (só JamJet conhece) ───
    check_consist = _checar_consistencia_notes_target(target_llm, frame_ldp, allowlist_dict)
    if check_consist is not None:
        return check_consist

    # ─── Camada 4: policy engine (amount/tool) ───
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


# ═══════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════

@app.route("/audit", methods=["POST"])
def audit_tool_call():
    t_inicio = time.perf_counter()
    dados = request.json

    frame_ldp = dados["frame_ldp"]
    decisao_llm = dados["decisao_llm"]

    policy_dict = carregar_politica()
    allowlist_dict = carregar_allowlist()
    resultado = auditar_com_jamjet(policy_dict, allowlist_dict, frame_ldp, decisao_llm)

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