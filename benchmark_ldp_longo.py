import time
import requests
import statistics
import json

URL = "http://127.0.0.1:1234/v1/chat/completions"

# Baseline Longo (Texto verboso original do artigo)
prompt_modo_0_longo = (
    "Olá, agente bancário. Por favor, solicito que você realize uma operação "
    "de transferência financeira interdomínio. O valor a ser transferido é de "
    "cem reais brasileiros (R$ 100,00). O favorecido desta operação deve ser "
    "a conta identificada no sistema como fornecedor_xyz. Aguardo a execução."
)

payload_modo_0 = {
    "model": "qwen2.5-3b-instruct",
    "messages": [
        {"role": "system", "content": "Você é um agente bancário de destino operando chamadas de ferramentas."},
        {"role": "user", "content": prompt_modo_0_longo}
    ],
    "temperature": 0.0
}

# LDP Equivalente
frame_ldp = {
    "task_type": "payment_execution",
    "action": "transfer_funds",
    "params": {
        "amount": 100.0,
        "currency": "BRL",
        "recipient": "fornecedor_xyz"
    }
}

payload_modo_1 = {
    "model": "qwen2.5-3b-instruct",
    "messages": [
        {"role": "system", "content": "Você é um agente bancário de destino operando chamadas de ferramentas."},
        {"role": "user", "content": json.dumps(frame_ldp)}
    ],
    "temperature": 0.0
}

def executar_bateria(payload, nome_teste, n=30):
    print(f"Executando {nome_teste} ({n} iterações)...")
    latencias = []
    tokens_in = []
    
    for i in range(n):
        t0 = time.perf_counter()
        try:
            resp = requests.post(URL, json=payload).json()
            latencia_total = time.perf_counter() - t0
            
            latencias.append(latencia_total)
            tokens_in.append(resp.get("usage", {}).get("prompt_tokens", 0))
            
            print(f"  [{i+1}/{n}] Ok", end="\r")
        except Exception as e:
            print(f"\nErro na iteração {i}: {e}")
            break
            
    media_lat = statistics.mean(latencias)
    desvio_lat = statistics.stdev(latencias) if n > 1 else 0
    
    print(f"\n--- Resultados {nome_teste} ---")
    print(f"Tokens de Entrada (Prefill): {tokens_in[0]}")
    print(f"Latência Total: {media_lat:.3f}s ± {desvio_lat:.3f}s\n")
    return tokens_in[0], media_lat

if __name__ == "__main__":
    print("--- BENCHMARK LDP: PONTO DE EQUILÍBRIO (FRASES LONGAS) ---\n")
    t_in_0, lat_0 = executar_bateria(payload_modo_0, "Modo 0 (Natural Longo)")
    t_in_1, lat_1 = executar_bateria(payload_modo_1, "Modo 1 (LDP)")
    
    economia_tokens = ((t_in_0 - t_in_1) / t_in_0) * 100
    economia_latencia = ((lat_0 - lat_1) / lat_0) * 100
    
    print("--- CONCLUSÃO ESTATÍSTICA (N=30) ---")
    print(f"Redução no payload de entrada: {economia_tokens:.1f}%")
    print(f"Impacto na latência total: {economia_latencia:.1f}%")
