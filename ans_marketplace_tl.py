import json
import time
import base64
import hashlib
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)

# Chaves Criptográficas ES256 (ECDSA P-256 / SHA-256) conforme Seção 5.6 (Tabela 7) do ANS v2
priv_ra_key = ec.generate_private_key(ec.SECP256R1())
priv_kms_key = ec.generate_private_key(ec.SECP256R1())

def pub_key_to_pem(priv_key):
    return priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

def jcs_canonicalize(obj):
    """Canonização determinística JCS (RFC 8785) exigida na Seção 5.6 do ANS v2."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def jws_detached_sign(priv_key, payload_dict, kid, typ="ans-event+json"):
    """Gera assinatura JWS Compact Detached (<header>..<signature>) com ES256 (Seção 5.6)."""
    header = {
        "alg": "ES256",
        "kid": kid,
        "typ": typ,
        "timestamp": int(time.time()),
        "raId": "ra-mocia-01"
    }
    header_b64 = base64.urlsafe_b64encode(jcs_canonicalize(header)).decode("utf-8").rstrip("=")
    payload_bytes = jcs_canonicalize(payload_dict)
    signing_input = header_b64.encode("utf-8") + b"." + payload_bytes
    sig_der = priv_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    sig_b64 = base64.urlsafe_b64encode(sig_der).decode("utf-8").rstrip("=")
    return f"{header_b64}..{sig_b64}"

# -------------------------------------------------------------------------
# REGISTRO INICIAL DOS DOIS AGENTES NO TRANSPARENCY LOG E MARKETPLACE
# -------------------------------------------------------------------------

# 1. Trust Card original que foi selado na RA para o Agente 1 (Impostor/Adulterado depois)
trust_card_impostor_selado = {
    "ansName": "ans://v1.0.0.pagamentos-rapidos.internal",
    "agentDisplayName": "FastPay Agent (Terceirizado)",
    "version": "1.0.0",
    "agentHost": "ahp_agente_impostor:8002",
    "releaseChannel": "stable",
    "endpoints": [
        {
            "protocol": "LDP-HTTP",
            "agentUrl": "http://ahp_agente_impostor:8002/api/ldp",
            "metadataUrl": "http://ahp_agente_impostor:8002/.well-known/ans/trust-card.json",
            "functions": [{"id": "executar_pagamento", "name": "Executar Pagamento", "tags": ["payment", "finance"]}]
        }
    ],
    "verifiableClaims": []
}

# 2. Trust Card oficial selado na RA para o Agente 2 (Agente Financeiro Oficial MOCIA)
trust_card_legitimo_selado = {
    "ansName": "ans://v1.0.0.financeiro.mocia.internal",
    "agentDisplayName": "Agente Financeiro Oficial MOCIA",
    "version": "1.0.0",
    "agentHost": "ahp_agente_financeiro:8001",
    "releaseChannel": "stable",
    "endpoints": [
        {
            "protocol": "LDP-HTTP",
            "agentUrl": "http://ahp_agente_financeiro:8001/api/ldp",
            "metadataUrl": "http://ahp_agente_financeiro:8001/.well-known/ans/trust-card.json",
            "functions": [{"id": "executar_pagamento", "name": "Executar Pagamento", "tags": ["payment", "finance"]}]
        }
    ],
    "verifiableClaims": [
        {"type": "SOC2_TYPE2", "issuer": "did:web:auditor.mocia.internal", "issuedAt": "2026-01-15T00:00:00Z"}
    ]
}

def criar_evento_tl(agent_id, seq_num, trust_card, server_cert_fp, identity_cert_fp):
    card_hash = hashlib.sha256(jcs_canonicalize(trust_card)).hexdigest()
    evento = {
        "ansId": agent_id,
        "ansName": trust_card["ansName"],
        "eventType": "AGENT_REGISTERED",
        "sequenceNumber": seq_num,
        "agent": {
            "host": trust_card["agentHost"],
            "name": trust_card["agentDisplayName"],
            "version": f"v{trust_card['version']}",
            "providerId": f"PID-00{seq_num}"
        },
        "attestations": {
            "agentCardHash": f"SHA256:{card_hash}",
            "identityCert": {"fingerprint": f"SHA256:{identity_cert_fp}", "type": "X509-PRIVATE-URI-SAN"},
            "serverCert": {"fingerprint": f"SHA256:{server_cert_fp}", "type": "X509-DV-SERVER"},
            "dnsRecordsProvisioned": {
                "_ans": f"v=ans1; version=v{trust_card['version']}; p=http; url={trust_card['endpoints'][0]['metadataUrl']}",
                "_ans-badge": f"v=ans-badge1; version=v{trust_card['version']}; url=http://ans_marketplace_tl:8000/v1/agents/{agent_id}",
                "_443._tcp_tlsa": f"3 0 1 {server_cert_fp}"
            }
        },
        "dnssecStatus": "fully_validated",
        "raId": "ra-mocia-01",
        "timestamp": "2026-10-16T12:00:00Z"
    }
    leaf_hash = hashlib.sha256(jcs_canonicalize(evento)).hexdigest()
    sig_ra = jws_detached_sign(priv_ra_key, evento, kid="ra-key-01")
    return evento, leaf_hash, sig_ra

ev1, leaf1, sig1 = criar_evento_tl(
    "agent-impostor-001", 1, trust_card_impostor_selado,
    server_cert_fp="a1b2c3d4e5f601", identity_cert_fp="f1e2d3c4b5a601"
)
ev2, leaf2, sig2 = criar_evento_tl(
    "agent-mocia-fin-002", 2, trust_card_legitimo_selado,
    server_cert_fp="998877665544aa", identity_cert_fp="112233445566bb"
)

# Raiz da Árvore de Merkle do Transparency Log (Seção 9.1)
merkle_root = hashlib.sha256((leaf1 + leaf2).encode("utf-8")).hexdigest()
checkpoint_payload = {
    "treeSize": 2,
    "treeVersion": 1,
    "rootHash": merkle_root,
    "timestamp": "2026-10-16T12:05:00Z"
}
checkpoint_sig = jws_detached_sign(priv_kms_key, checkpoint_payload, kid="kms-root-01", typ="scitt-checkpoint+json")

TL_DATABASE = {
    "agent-impostor-001": {
        "schemaVersion": "V1",
        "status": "ACTIVE",
        "payload": {"event": ev1, "producer": {"keyId": "ra-key-01", "signature": sig1}},
        "inclusionProof": {
            "leafHash": leaf1,
            "leafIndex": 0,
            "treeSize": 2,
            "treeVersion": 1,
            "path": [leaf2],
            "rootHash": merkle_root,
            "rootSignature": checkpoint_sig
        }
    },
    "agent-mocia-fin-002": {
        "schemaVersion": "V1",
        "status": "ACTIVE",
        "payload": {"event": ev2, "producer": {"keyId": "ra-key-01", "signature": sig2}},
        "inclusionProof": {
            "leafHash": leaf2,
            "leafIndex": 1,
            "treeSize": 2,
            "treeVersion": 1,
            "path": [leaf1],
            "rootHash": merkle_root,
            "rootSignature": checkpoint_sig
        }
    }
}

@app.route("/v1/discover", methods=["GET"])
def discover_agents():
    """Endpoint do Marketplace (Discovery Service) indexando agentes por função/tag."""
    func_filter = request.args.get("function", "executar_pagamento")
    print(f"\n[MARKETPLACE ANS] Busca recebida por função: '{func_filter}'", flush=True)
    candidatos = [
        {
            "agentId": "agent-impostor-001",
            "ansName": ev1["ansName"],
            "agentDisplayName": ev1["agent"]["name"],
            "agentHost": ev1["agent"]["host"],
            "trustCardUrl": trust_card_impostor_selado["endpoints"][0]["metadataUrl"],
            "badgeUrl": f"http://ans_marketplace_tl:8000/v1/agents/agent-impostor-001",
            "dns_ans_txt": ev1["attestations"]["dnsRecordsProvisioned"]["_ans"],
            "dns_tlsa": ev1["attestations"]["dnsRecordsProvisioned"]["_443._tcp_tlsa"]
        },
        {
            "agentId": "agent-mocia-fin-002",
            "ansName": ev2["ansName"],
            "agentDisplayName": ev2["agent"]["name"],
            "agentHost": ev2["agent"]["host"],
            "trustCardUrl": trust_card_legitimo_selado["endpoints"][0]["metadataUrl"],
            "badgeUrl": f"http://ans_marketplace_tl:8000/v1/agents/agent-mocia-fin-002",
            "dns_ans_txt": ev2["attestations"]["dnsRecordsProvisioned"]["_ans"],
            "dns_tlsa": ev2["attestations"]["dnsRecordsProvisioned"]["_443._tcp_tlsa"]
        }
    ]
    return jsonify({"marketplace_results": candidatos})

@app.route("/v1/agents/<agent_id>", methods=["GET"])
def get_tl_badge(agent_id):
    """Endpoint oficial do Transparency Log (Tabela 2 e Apêndice A.4 do ANS v2)."""
    print(f"[TRANSPARENCY LOG] Emitindo Badge e Inclusion Proof para: {agent_id}", flush=True)
    if agent_id not in TL_DATABASE:
        return jsonify({"error": "Agent not found in TL"}), 404
    return jsonify(TL_DATABASE[agent_id])

@app.route("/v1/log/checkpoint", methods=["GET"])
def get_checkpoint():
    """Retorna o Checkpoint assinado pelo KMS (Tabela 2 do ANS v2)."""
    return jsonify({"checkpoint": checkpoint_payload, "kmsSignature": checkpoint_sig})

@app.route("/root-keys", methods=["GET"])
def get_root_keys():
    """Distribui as chaves públicas da RA e do KMS para verificação sem contato com a RA (Seção 4.3)."""
    return jsonify({
        "keys": {
            "ra-key-01": pub_key_to_pem(priv_ra_key),
            "kms-root-01": pub_key_to_pem(priv_kms_key)
        }
    })

if __name__ == "__main__":
    print("ANS v2 Marketplace & Transparency Log ativo na porta 8000...", flush=True)
    app.run(host="0.0.0.0", port=8000)