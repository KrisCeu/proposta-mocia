import time
import requests
import statistics
import json

URL = "http://127.0.0.1:1234/v1/chat/completions"

# --- CENÁRIOS CURTOS ---
payload_curto_0 = {
    "model": "qwen2.5-3b-instruct",
    "messages": [
        {"role": "system", "content": "Você é um agente bancário de destino operando chamadas de ferramentas."},
        {"role": "user", "content": "Transfira R$ 100,00 para fornecedor_xyz"}
    ],
    "temperature": 0.0,
    "max_tokens": 10 # <-- Variável de controle: Força a paridade de saída
}

payload_curto_1 = {
    "model": "qwen2.5-3b-instruct",
    "messages": [
        {"role": "system", "content": "Você é um agente bancário de destino operando chamadas de ferramentas."},
        {"role": "user", "content": json.dumps({"transfer": {"amount": 100.0, "to": "fornecedor_xyz"}})}
    ],
    "temperature": 0.0,
    "max_tokens": 10 # <-- Variável de controle
}

# --- CENÁRIOS LONGOS ---
prompt_longo = (
    "Olá, agente bancário. Por favor, solicito que você realize uma operação "
    "de transferência financeira interdomínio. O valor a ser transferido é de "
    "cem reais brasileiros (R$ 100,00). O favorecido desta operação deve ser "
    "a conta identificada no sistema como fornecedor_xyz. Aguardo a execução."
)
payload_longo_0 = {
    "model": "qwen2.5-3b-instruct",
    "messages": [
        {"role": "system", "content": "Você é um agente bancário de destino operando chamadas de ferramentas."},
        {"role": "user", "content": prompt_longo}
    ],
    "temperature": 0.0,
    "max_tokens": 10 # <-- Variável de controle
}

frame_ldp_longo = {
    "task_type": "payment_execution",
    "action": "transfer_funds",
    "params": {
        "amount": 100.0,
        "currency": "BRL",
        "recipient": "fornecedor_xyz"
    }
}
payload_longo_1 = {
    "model": "qwen2.5-3b-instruct",
    "messages": [
        {"role": "system", "content": "Você é um agente bancário de destino operando chamadas de ferramentas."},
        {"role": "user", "content": json.dumps(frame_ldp_longo)}
    ],
    "temperature": 0.0,
    "max_tokens": 10 # <-- Variável de controle
}

def executar_bateria(payload, nome_teste, n=30):
    print(f"\nExecutando {nome_teste} ({n} iterações)...")
    latencias = []
    tokens_in = []
    tokens_out = []
    
    for i in range(n):
        t0 = time.perf_counter()
        try:
            resp = requests.post(URL, json=payload).json()
            latencia_total = time.perf_counter() - t0
            
            latencias.append(latencia_total)
            
            usage = resp.get("usage", {})
            tokens_in.append(usage.get("prompt_tokens", 0))
            tokens_out.append(usage.get("completion_tokens", 0))
            
            print(f"  [{i+1}/{n}] Ok", end="\r")
        except Exception as e:
            print(f"\nErro na iteração {i}: {e}")
            break
            
    media_lat = statistics.mean(latencias)
    desvio_lat = statistics.stdev(latencias) if n > 1 else 0
    t_in = tokens_in[0] if tokens_in else 0
    t_out = statistics.mean(tokens_out) if tokens_out else 0
    
    print(f"\n--- Resultados {nome_teste} ---")
    print(f"Tokens de Entrada (Lidos)   : {t_in}")
    print(f"Tokens de Saída (Gerados)   : {t_out:.1f} (Controle Paritário)")
    print(f"Latência de Processamento   : {media_lat:.3f}s ± {desvio_lat:.3f}s")
    return t_in, media_lat

if __name__ == "__main__":
    print("=== INICIANDO BENCHMARK DEFINITIVO LDP (PARIDADE DE TOKENS) ===")
    
    t_in_c0, lat_c0 = executar_bateria(payload_curto_0, "1. Curto - Modo 0 (Natural)")
    t_in_c1, lat_c1 = executar_bateria(payload_curto_1, "2. Curto - Modo 1 (LDP)")
    
    t_in_l0, lat_l0 = executar_bateria(payload_longo_0, "3. Longo - Modo 0 (Natural)")
    t_in_l1, lat_l1 = executar_bateria(payload_longo_1, "4. Longo - Modo 1 (LDP)")
    
    print("\n=== CONCLUSÕES FINAIS (COMPETIÇÃO PAR A PAR) ===")
    
    print("\nCENÁRIO CURTO:")
    print(f"Diferença de Payload: {((t_in_c0 - t_in_c1) / t_in_c0) * 100:.1f}%")
    print(f"Impacto na Latência : {((lat_c0 - lat_c1) / lat_c0) * 100:.1f}%")
    
    print("\nCENÁRIO LONGO:")
    print(f"Diferença de Payload: {((t_in_l0 - t_in_l1) / t_in_l0) * 100:.1f}%")
    print(f"Impacto na Latência : {((lat_l0 - lat_l1) / lat_l0) * 100:.1f}%")
