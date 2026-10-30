import time
import requests
import json
import yaml
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import hashes

# Configurações
URL = "http://127.0.0.1:1234/v1/chat/completions"
POLITICA_YAML = """
limites:
  transferencia_maxima: 200.00
"""

def testar_pipeline_completo():
    print("=== INICIANDO BENCHMARK PONTA A PONTA (E2E) ===")
    print("Arquitetura de Defesa em Profundidade (Camadas 1 a 4)\n")
    
    tempos = {}
    t_inicio_pipeline = time.perf_counter()

    # ---------------------------------------------------------
    # CAMADA 1: SAGA (Handshake e Derivação de Chave)
    # ---------------------------------------------------------
    print("[1/4] Executando Camada 1 (SAGA)...")
    t0 = time.perf_counter()
    priv_iniciador = x25519.X25519PrivateKey.generate()
    priv_destino = x25519.X25519PrivateKey.generate()
    chave_compartilhada = priv_iniciador.exchange(priv_destino.public_key())
    tempos['SAGA'] = time.perf_counter() - t0

    # ---------------------------------------------------------
    # CAMADA 3: LDP (Leitura e Geração de Tool Call pela LLM)
    # ---------------------------------------------------------
    print("[2/4] Executando Camada 3 (LDP -> Roteamento para LLM)...")
    t0 = time.perf_counter()
    frame_ldp = {"task": "pay", "amount": 100.0, "currency": "BRL", "recipient": "fornecedor_xyz"}
    payload = {
        "model": "qwen2.5-3b-instruct",
        "messages": [
            {"role": "system", "content": "Extraia os dados e retorne APENAS um JSON válido com a intenção de ação."},
            {"role": "user", "content": json.dumps(frame_ldp)}
        ],
        "temperature": 0.0
    }
    
    try:
        resposta_llm = requests.post(URL, json=payload).json()
        conteudo_gerado = resposta_llm['choices'][0]['message']['content']
        print("\n--- INÍCIO DA RESPOSTA GERADA PELA IA ---")
        print(conteudo_gerado)
        print("--- FIM DA RESPOSTA GERADA PELA IA ---\n")
    except Exception as e:
        print(f"Erro na comunicação com a LLM: {e}")
        return
    tempos['LLM_LDP'] = time.perf_counter() - t0

    # ---------------------------------------------------------
    # CAMADA 4: JamJet (Interceptação e Validação Determinística)
    # ---------------------------------------------------------
    print("[3/4] Executando Camada 4 (JamJet Policy Engine)...")
    t0 = time.perf_counter()
    regras = yaml.safe_load(POLITICA_YAML)
    teto_permitido = regras['limites']['transferencia_maxima']
    
    # Simulando a extração do valor que a LLM tentou passar para a ferramenta
    valor_solicitado = frame_ldp['amount'] 
    
    if valor_solicitado <= teto_permitido:
        status_jamjet = "APROVADO"
    else:
        status_jamjet = "BLOQUEADO (HITL)"
    tempos['JamJet'] = time.perf_counter() - t0

    # ---------------------------------------------------------
    # CAMADA 2: ANS (Assinatura do Recibo)
    # ---------------------------------------------------------
    print(f"[4/4] Executando Camada 2 (ANS) - Assinando recibo {status_jamjet}...")
    t0 = time.perf_counter()
    priv_key = ec.generate_private_key(ec.SECP256R1())
    recibo = f'{{"status": "{status_jamjet}", "tx_id": "999"}}'.encode('utf-8')
    assinatura = priv_key.sign(recibo, ec.ECDSA(hashes.SHA256()))
    tempos['ANS'] = time.perf_counter() - t0

    # ---------------------------------------------------------
    # RESULTADOS
    # ---------------------------------------------------------
    tempo_total = time.perf_counter() - t_inicio_pipeline
    
    print("\n=== RESULTADOS DA COMPOSIÇÃO (LATÊNCIA) ===")
    print(f"Camada 1 (SAGA)    : {tempos['SAGA']*1000:.4f} ms")
    print(f"Camada 3 (LLM/LDP) : {tempos['LLM_LDP']*1000:.4f} ms  <-- Gargalo Cognitivo")
    print(f"Camada 4 (JamJet)  : {tempos['JamJet']*1000:.4f} ms")
    print(f"Camada 2 (ANS)     : {tempos['ANS']*1000:.4f} ms")
    print("-" * 45)
    print(f"TEMPO TOTAL (E2E)  : {tempo_total:.4f} segundos")
    
    # Cálculo do overhead
    overhead_seguranca_ms = (tempos['SAGA'] + tempos['JamJet'] + tempos['ANS']) * 1000
    proporcao_seguranca = (overhead_seguranca_ms / (tempo_total * 1000)) * 100
    
    print(f"\nO custo de TODAS as camadas de segurança juntas foi de {overhead_seguranca_ms:.4f} ms.")
    print(f"Isso representa apenas {proporcao_seguranca:.5f}% do tempo total da transação.")

if __name__ == "__main__":
    testar_pipeline_completo()
