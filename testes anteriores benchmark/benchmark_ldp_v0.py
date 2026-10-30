import time
import requests
import json

# Endpoint padrão do LM Studio
URL = "http://127.0.0.1:1234/v1/chat/completions"

# ---------------------------------------------------------
# Teste A: MODO 0 - Linguagem Natural Verbosa (Padrão do Artigo)
# ---------------------------------------------------------
prompt_modo_0 = (
    "Olá, agente bancário. Por favor, solicito que você realize uma operação "
    "de transferência financeira interdomínio. O valor a ser transferido é de "
    "cem reais brasileiros (R$ 100,00). O favorecido desta operação deve ser "
    "a conta identificada no sistema como fornecedor_xyz. Aguardo a execução."
)

payload_modo_0 = {
    "model": "qwen2.5-3b-instruct",
    "messages": [
        {"role": "system", "content": "Você é um agente bancário de destino."},
        {"role": "user", "content": prompt_modo_0}
    ],
    "temperature": 0.0
}

# ---------------------------------------------------------
# Teste B: MODO 1 - LDP Semantic Frame (JSON Tipado)
# ---------------------------------------------------------
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
        {"role": "system", "content": "Você é um agente bancário de destino."},
        {"role": "user", "content": json.dumps(frame_ldp)}
    ],
    "temperature": 0.0
}

def medir_consumo(payload, nome_teste):
    print(f"Executando {nome_teste}...")
    t0 = time.perf_counter()
    
    try:
        resposta = requests.post(URL, json=payload).json()
    except Exception as e:
        print(f"Erro ao conectar com o LM Studio: {e}")
        return 0
        
    tempo_total = time.perf_counter() - t0
    
    # Extrai a contagem de tokens que o modelo precisou ler
    prompt_tokens = resposta.get("usage", {}).get("prompt_tokens", 0)
    
    print(f"  -> Latência de leitura: {tempo_total:.3f} s")
    print(f"  -> Tokens consumidos (Payload de Entrada): {prompt_tokens}\n")
    
    return prompt_tokens

if __name__ == "__main__":
    print("--- INICIANDO BENCHMARK DE TRANSPORTE LDP (V0 - REPRODUÇÃO DO ARTIGO) ---\n")
    
    tokens_modo_0 = medir_consumo(payload_modo_0, "Modo 0 (Texto Livre)")
    time.sleep(2) # Pausa original de 2s
    tokens_modo_1 = medir_consumo(payload_modo_1, "Modo 1 (Semantic Frame)")
    
    if tokens_modo_0 > 0 and tokens_modo_1 > 0:
        reducao = ((tokens_modo_0 - tokens_modo_1) / tokens_modo_0) * 100
        print("--- RESULTADOS FINAIS ---")
        print(f"Economia de processamento cognitivo (tokens): {reducao:.2f}%")
