"""
Proxy LLM: recebe chamadas OpenAI-compatíveis dos agentes MOCIA
e as encaminha ao llama.cpp remoto via Tailscale, injetando a API key
e reescrevendo o nome do modelo.
"""
import os
import time
import logging
import requests
from flask import Flask, request, Response

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("llm_gateway")

UPSTREAM_URL = os.getenv("LLM_UPSTREAM_URL", "http://100.127.32.71:18080")
UPSTREAM_CHAT = f"{UPSTREAM_URL}/v1/chat/completions"
API_KEY = os.getenv("QWEN_API_KEY", "")
MODEL_OVERRIDE = os.getenv("LLM_MODEL_OVERRIDE", "")  # vazio = não sobrescreve
REQUEST_TIMEOUT = float(os.getenv("LLM_TIMEOUT_S", "300"))

if not API_KEY:
    log.warning("QWEN_API_KEY não definida — requisições irão sem Authorization header.")

app = Flask(__name__)


@app.route("/v1/chat/completions", methods=["POST"])
def proxy_chat():
    t0 = time.perf_counter()
    payload = request.get_json(force=True, silent=True) or {}

    model_original = payload.get("model", "?")
    if MODEL_OVERRIDE:
        payload["model"] = MODEL_OVERRIDE

    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"

    try:
        r = requests.post(
            UPSTREAM_CHAT,
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        elapsed = time.perf_counter() - t0
        log.error(f"[timeout {elapsed:.1f}s] model={payload['model']} upstream={UPSTREAM_CHAT}")
        return Response(
            '{"error":"upstream timeout","detail":"llama.cpp não respondeu a tempo"}',
            status=504,
            mimetype="application/json",
        )
    except Exception as e:
        elapsed = time.perf_counter() - t0
        log.error(f"[erro {elapsed:.1f}s] {type(e).__name__}: {e}")
        return Response(
            f'{{"error":"upstream unreachable","detail":"{type(e).__name__}: {e}"}}',
            status=502,
            mimetype="application/json",
        )

    elapsed = time.perf_counter() - t0
    model_used = payload["model"]
    override_tag = f" (override de {model_original})" if model_original != model_used else ""
    log.info(
        f"[{r.status_code} {elapsed:.2f}s] model={model_used}{override_tag} "
        f"prompt_tokens≈{len(str(payload.get('messages', '')))}b"
    )

    if r.status_code != 200:
        log.warning(f"upstream {r.status_code}: {r.text[:300]}")

    return Response(r.content, status=r.status_code, mimetype="application/json")


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok", "upstream": UPSTREAM_CHAT, "model_override": MODEL_OVERRIDE or "(none)"}


if __name__ == "__main__":
    log.info(f"LLM Gateway ativo — upstream={UPSTREAM_CHAT} model={MODEL_OVERRIDE or '(passthrough)'}")
    app.run(host="0.0.0.0", port=1235)