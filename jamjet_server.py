import json
import os
import time
import unicodedata
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify
import yaml

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
POLICY_PATH = BASE_DIR / "jamjet_policy.yaml"
ALLOWLIST_PATH = BASE_DIR / "allowlist.yaml"
AUDIT_LOG_PATH = BASE_DIR / "audit_trail.jsonl"


# ═══════════════════════════════════════════════════════════════════
# Estado de agregação (fix T5: structuring detection)
# ═══════════════════════════════════════════════════════════════════
_AGGREGATE_LOCK = threading.Lock()
_AGGREGATE_STATE = {}  # {(target_norm, window_bucket): {"sum": float, "count": int}}


# ═══════════════════════════════════════════════════════════════════
# Overrides de configuração em runtime (experimento T8)
# ═══════════════════════════════════════════════════════════════════
# Permite ao runner de testes alternar controles de segurança SEM editar
# allowlist.yaml (montado read-only) nem reiniciar o container, garantindo
# que as duas configurações comparadas rodem contra o mesmo processo.
# Só chaves desta whitelist podem ser sobrescritas, e só com valores válidos.
_OVERRIDE_LOCK = threading.Lock()
_OVERRIDES = {}  # {"security_controls.on_recipient_inconsistency": "deny"}
_OVERRIDES_PERMITIDOS = {
    "security_controls.on_recipient_inconsistency": {"log", "deny", "require_approval_for"},
}


def _aplicar_overrides(allowlist_dict: dict) -> dict:
    with _OVERRIDE_LOCK:
        overrides = dict(_OVERRIDES)
    for chave, valor in overrides.items():
        secao, campo = chave.split(".", 1)
        allowlist_dict.setdefault(secao, {})[campo] = valor
    return allowlist_dict


def _load_yaml(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def carregar_politica() -> dict:
    """Lê jamjet_policy.yaml. Exclusivo do JamJet — a LLM não vê este arquivo."""
    policy = _load_yaml(POLICY_PATH)
    if not policy:
        return {"budget_limits": {"max_transaction_value": 200.00}, "rules": []}
    return policy


def carregar_allowlist() -> dict:
    """Lê allowlist.yaml e aplica overrides de runtime (se houver).
    Exclusivo do JamJet — não vai para o prompt da LLM."""
    return _aplicar_overrides(_load_yaml(ALLOWLIST_PATH))


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
# Helpers
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


def _safe_float(value, default=None):
    """Converte para float, ou retorna default se não for numérico.
    Evita HTTP 500 quando a LLM retorna amount=null ou string não-numérica."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _get_window_bucket(window_seconds: int) -> int:
    """Retorna o índice do bucket temporal atual.
    Transações no mesmo bucket caem na mesma janela de agregação."""
    return int(time.time() // max(1, window_seconds))


# ═══════════════════════════════════════════════════════════════════
# Checagens com allowlist
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
# Agregação por destinatário/janela (fix T5)
# ═══════════════════════════════════════════════════════════════════

def _checar_agregacao_pre(target: str, amount: float, policy_dict: dict):
    """
    Verifica (sem incrementar) se a transação estouraria o teto agregado
    por destinatário na janela temporal configurada.

    Retorna dict JamJet se estourar, senão None.
    """
    limits = policy_dict.get("budget_limits", {})
    max_agg = limits.get("max_aggregate_per_target")
    if max_agg is None:
        return None  # agregação desabilitada

    window_s = int(limits.get("aggregation_window_seconds", 60))
    on_exceed = limits.get("on_aggregate_exceeded", "deny")

    target_key = _normalizar(target)
    bucket = _get_window_bucket(window_s)
    key = (target_key, bucket)

    with _AGGREGATE_LOCK:
        current = _AGGREGATE_STATE.get(key, {"sum": 0.0, "count": 0})
        novo_total = current["sum"] + amount

        if novo_total > float(max_agg):
            return {
                "jamjet_action": on_exceed,
                "divergencia_detectada": False,
                "motivo_jamjet": (
                    f"STRUCTURING DETECTADO: transação de R$ {amount:.2f} "
                    f"para '{target}' somaria R$ {novo_total:.2f} na janela de "
                    f"{window_s}s (teto agregado: R$ {float(max_agg):.2f}). "
                    f"Histórico na janela: {current['count']} tx, R$ {current['sum']:.2f}."
                ),
            }
    return None


def _registrar_agregado(target: str, amount: float, policy_dict: dict) -> None:
    """Incrementa o agregado APÓS decisão 'allow'. Nunca chamado para deny/require_approval."""
    limits = policy_dict.get("budget_limits", {})
    if limits.get("max_aggregate_per_target") is None:
        return

    window_s = int(limits.get("aggregation_window_seconds", 60))
    target_key = _normalizar(target)
    bucket = _get_window_bucket(window_s)
    key = (target_key, bucket)

    with _AGGREGATE_LOCK:
        current = _AGGREGATE_STATE.get(key, {"sum": 0.0, "count": 0})
        _AGGREGATE_STATE[key] = {
            "sum": current["sum"] + amount,
            "count": current["count"] + 1,
        }


# ═══════════════════════════════════════════════════════════════════
# Função principal de auditoria
# ═══════════════════════════════════════════════════════════════════

def auditar_com_jamjet(policy_dict, allowlist_dict, frame_ldp, decisao_llm):
    tool_llm = decisao_llm.get("tool")
    action_llm = decisao_llm.get("action")
    target_llm = decisao_llm.get("target")
    target_ldp = frame_ldp.get("target")
    tool_ldp = frame_ldp.get("requested_tool")

    # ─── Camada 0: conversão segura de amount + sinal ───
    amount_llm = _safe_float(decisao_llm.get("amount"), default=None)
    amount_ldp = _safe_float(frame_ldp.get("amount"), default=None)

    if amount_llm is None or amount_ldp is None:
        return {
            "jamjet_action": "deny",
            "divergencia_detectada": True,
            "motivo_jamjet": (
                f"ENTRADA INVÁLIDA: amount não numérico "
                f"(LLM={decisao_llm.get('amount')!r}, LDP={frame_ldp.get('amount')!r})."
            ),
        }

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

    # ─── Camada 4: agregação por destinatário/janela (fix T5) ───
    check_agg = _checar_agregacao_pre(target_llm, amount_llm, policy_dict)
    if check_agg is not None:
        return check_agg

    # ─── Camada 5: policy engine (amount/tool) ───
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

    # ─── Incrementa agregado APÓS decisão final (só se allow) ───
    if acao_esperada == "allow":
        _registrar_agregado(target_llm, amount_llm, policy_dict)

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

    with _OVERRIDE_LOCK:
        overrides_ativos = dict(_OVERRIDES)

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
            "overrides_ativos": overrides_ativos,
        },
    )

    return jsonify({
        "jamjet_action": resultado["jamjet_action"],
        "divergencia_detectada": resultado["divergencia_detectada"],
        "motivo_jamjet": resultado["motivo_jamjet"],
        "eval_latency_ms": round(latencia_ms, 3),
    })


@app.route("/admin/reset-aggregate", methods=["POST"])
def reset_aggregate():
    """
    Reseta o estado de agregação. Usado pelos testes para garantir que cada
    iteração seja avaliada independentemente (sem herdar o agregado de runs anteriores).

    Em produção, este endpoint deve ser protegido (auth + restrito a loopback).
    Aqui é aberto porque é um PoC e o JamJet não é exposto externamente.
    """
    global _AGGREGATE_STATE
    with _AGGREGATE_LOCK:
        _AGGREGATE_STATE = {}
    return jsonify({"status": "ok", "aggregate_state": "cleared"})


@app.route("/admin/override", methods=["GET", "POST", "DELETE"])
def admin_override():
    """
    Overrides de configuração em runtime, usados pelo experimento T8 para
    comparar on_recipient_inconsistency=log vs deny no mesmo processo.

      GET    → lista overrides ativos
      POST   {"security_controls.on_recipient_inconsistency": "deny"} → aplica
      DELETE → remove todos (volta ao allowlist.yaml)

    Mesma ressalva do reset-aggregate: em produção exigiria auth + loopback.
    """
    if request.method == "DELETE":
        with _OVERRIDE_LOCK:
            _OVERRIDES.clear()
        return jsonify({"status": "ok", "overrides": {}})

    if request.method == "POST":
        dados = request.get_json(silent=True) or {}
        erros = {}
        aceitos = {}
        for chave, valor in dados.items():
            validos = _OVERRIDES_PERMITIDOS.get(chave)
            if validos is None:
                erros[chave] = "chave não permitida"
            elif valor not in validos:
                erros[chave] = f"valor inválido (use {sorted(validos)})"
            else:
                aceitos[chave] = valor
        if erros:
            return jsonify({"status": "erro", "erros": erros}), 400
        with _OVERRIDE_LOCK:
            _OVERRIDES.update(aceitos)

    with _OVERRIDE_LOCK:
        atuais = dict(_OVERRIDES)
    return jsonify({"status": "ok", "overrides": atuais})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    PORTA = int(os.getenv("PORTA_JAMJET", "8004"))
    print(f"JamJet Action-Control Service ativo na porta {PORTA}...", flush=True)
    app.run(host="0.0.0.0", port=PORTA)