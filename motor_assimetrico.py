from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class CriptografiaAssimetrica:
    def __init__(self):
        # Gera o par de chaves RSA de 2048 bits
        self.chave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.chave_publica = self.chave_privada.public_key()

    def cifrar_mensagem(self, mensagem_original: str) -> bytes:
        """Cifra a mensagem utilizando exclusivamente a CHAVE PÚBLICA."""
        mensagem_bytes = mensagem_original.encode('utf-8')
        mensagem_cifrada = self.chave_publica.encrypt(
            mensagem_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return mensagem_cifrada

    def decifrar_mensagem(self, mensagem_cifrada: bytes) -> str:
        """Decifra a mensagem utilizando a CHAVE PRIVADA."""
        mensagem_decifrada_bytes = self.chave_privada.decrypt(
            mensagem_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return mensagem_decifrada_bytes.decode('utf-8')

# --- Teste rápido no terminal ---
if __name__ == "__main__":
    motor_rsa = CriptografiaAssimetrica()
    print("Par de chaves RSA (2048 bits) gerado com sucesso!")
    
    texto_secreto = "Esta é uma mensagem segura para o teste assimétrico."
    print(f"\nTexto Original: {texto_secreto}")
    
    # Ciframos com a Pública
    cifrado = motor_rsa.cifrar_mensagem(texto_secreto)
    print(f"\nTexto Cifrado (Bytes em hexadecimal para visualização):\n{cifrado.hex()[:100]}... [truncado]")
    
    # Deciframos com a Privada
    decifrado = motor_rsa.decifrar_mensagem(cifrado)
    print(f"\nTexto Decifrado (Original recuperado): {decifrado}")