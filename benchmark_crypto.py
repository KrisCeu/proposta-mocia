import time
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import hashes

def benchmark_saga():
    print("Testando Camada 1: SAGA (Handshake Diffie-Hellman X25519)...")
    # Simulação da geração de chaves efêmeras para o túnel
    priv_iniciador = x25519.X25519PrivateKey.generate()
    priv_destino = x25519.X25519PrivateKey.generate()
    pub_destino = priv_destino.public_key()
    
    t0 = time.perf_counter()
    iteracoes = 1000
    for _ in range(iteracoes):
        chave_compartilhada = priv_iniciador.exchange(pub_destino)
    t1 = time.perf_counter()
    
    latencia_ms = ((t1 - t0) / iteracoes) * 1000
    print(f"  -> Latência média de derivação de chave: {latencia_ms:.4f} ms\n")

def benchmark_ans():
    print("Testando Camada 2: ANS (Assinatura e Verificação ECDSA)...")
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()
    
    # Simulação do payload do recibo da transação de R$ 100,00
    payload = b'{"resultado": "SUCESSO", "id_transacao": "tx_123", "valor": 100.0}'
    
    t0 = time.perf_counter()
    iteracoes = 1000
    for _ in range(iteracoes):
        assinatura = priv_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    t_sign = time.perf_counter()
    
    for _ in range(iteracoes):
        pub_key.verify(assinatura, payload, ec.ECDSA(hashes.SHA256()))
    t_verify = time.perf_counter()
    
    lat_sign_ms = ((t_sign - t0) / iteracoes) * 1000
    lat_verify_ms = ((t_verify - t_sign) / iteracoes) * 1000
    
    print(f"  -> Latência média para assinar o recibo: {lat_sign_ms:.4f} ms")
    print(f"  -> Latência média para verificar o recibo: {lat_verify_ms:.4f} ms\n")

if __name__ == "__main__":
    print("--- INICIANDO BENCHMARK CRIPTOGRÁFICO DAS CAMADAS 1 E 2 ---\n")
    benchmark_saga()
    benchmark_ans()
