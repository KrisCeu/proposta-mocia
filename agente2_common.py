"""
Módulo compartilhado entre os 3 arquivos de teste (testes.py, testes_infra.py,
testes_avancados.py).

Contém APENAS primitivas compartilhadas:
- Chaves ECDSA e X25519 do Agente 2 (geradas no startup do processo)
- Serialização canônica de frame para assinatura
- Reset do estado de agregação do JamJet
- URLs base e NUM_RUNS

Funções específicas do benchmark de 9 cenários (descoberta ANS, geração de
frame via LLM, runner de bateria, relatório) foram movidas para `testes.py`
para separar responsabilidades: este módulo é infraestrutura, `testes.py` é
o benchmark.
"""
import os
import json
import requests
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization


URL_LLM = os.getenv("URL_LLM", "http://127.0.0.1:1234/v1/chat/completions")
URL_JAMJET_ADMIN = os.getenv("URL_JAMJET_ADMIN", "http://jamjet_server:8004")
NUM_RUNS = 30


def reset_aggregate():
    """Reseta o estado de agregação do JamJet. Chamado antes de cada iteração
    de teste para garantir que cada run seja avaliado independentemente
    (sem herdar agregado de runs anteriores)."""
    try:
        requests.post(f"{URL_JAMJET_ADMIN}/admin/reset-aggregate", timeout=5)
    except Exception:
        pass  # silencioso — se o JamJet não responder, o teste continua


# ─── Chaves do Agente 2 (geradas no startup) ───
priv_agente2_ldp = ec.generate_private_key(ec.SECP256R1())
pub_agente2_ldp_pem = priv_agente2_ldp.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")

priv_agente2_saga = x25519.X25519PrivateKey.generate()
pub_agente2_hex = priv_agente2_saga.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
).hex()


def serializar_frame_para_assinatura(frame_ldp):
    return json.dumps(frame_ldp, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")