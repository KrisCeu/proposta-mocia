import time
import requests
import json
import statistics

URL = "http://127.0.0.1:1234/v1/chat/completions"

# Baseline Honesto (Linguagem Natural Realista)
prompt_modo_0 = "Transfira R$ 100,00 para a conta do fornecedor_xyz."

payload_modo_0 = {
    "model": "qwen2.5-3b-instruct",
    "messages": [
        {"role": "system", "content": "Você é um agente bancário de destino operando chamadas de ferramentas."},
        {"role": "user", "content": prompt_modo_0}
    ],
    "temperature": 0.0
}

# LDP (Semantic Frame Enxuto)
frame_ldp = {"task": "pay", "amount": 100.0, "currency": "BRL", "recipient": "fornecedor_xyz"}

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
    tokens_out = []
    
    for i in range(n):
        t0 = time.perf_counter()
        try:
            resp = requests.post(URL, json=payload).json()
            latencia_total = time.perf_counter() - t0
            
            latencias.append(latencia_total)
            tokens_in.append(resp.get("usage", {}).get("prompt_tokens", 0))
            tokens_out.append(resp.get("usage", {}).get("completion_tokens", 0))
            
            print(f"  [{i+1}/{n}] Ok", end="\r")
        except Exception as e:
            print(f"\nErro na iteração {i}: {e}")
            break
            
    media_lat = statistics.mean(latencias)
    desvio_lat = statistics.stdev(latencias) if n > 1 else 0
    
    print(f"\n--- Resultados {nome_teste} ---")
    print(f"Tokens de Entrada (Prefill): {tokens_in[0]} tokens (Constante)")
    print(f"Tokens de Saída (Geração Média): {statistics.mean(tokens_out):.1f} tokens")
    print(f"Latência Total: {media_lat:.3f}s ± {desvio_lat:.3f}s\n")
    
    return tokens_in[0], media_lat

if __name__ == "__main__":
    t_in_0, lat_0 = executar_bateria(payload_modo_0, "Modo 0 (Natural)")
    t_in_1, lat_1 = executar_bateria(payload_modo_1, "Modo 1 (LDP)")
    
    economia_tokens = ((t_in_0 - t_in_1) / t_in_0) * 100
    economia_latencia = ((lat_0 - lat_1) / lat_0) * 100
    
    print("--- CONCLUSÃO ESTATÍSTICA (N=30) ---")
    print(f"Redução no payload de entrada: {economia_tokens:.1f}%")
    print(f"Impacto na latência total: {economia_latencia:.1f}%")
