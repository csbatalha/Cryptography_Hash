from cryptography.fernet import Fernet

class CriptografiaSimetrica:
    def __init__(self):
        # Gera uma chave única de 32 bytes (codificada em base64) no momento da instância
        self.chave = Fernet.generate_key()
        self.fernet = Fernet(self.chave)

    def cifrar_mensagem(self, mensagem_original: str) -> bytes:
        """Recebe uma string, converte para bytes e retorna a mensagem cifrada."""
        mensagem_bytes = mensagem_original.encode('utf-8')
        mensagem_cifrada = self.fernet.encrypt(mensagem_bytes)
        return mensagem_cifrada

    def decifrar_mensagem(self, mensagem_cifrada: bytes) -> str:
        """Recebe os bytes cifrados, usa a MESMA chave para decifrar e retorna a string original."""
        mensagem_decifrada_bytes = self.fernet.decrypt(mensagem_cifrada)
        return mensagem_decifrada_bytes.decode('utf-8')

# --- Teste rápido no terminal ---
if __name__ == "__main__":
    motor = CriptografiaSimetrica()
    print(f"Chave gerada (Guarde-a com segurança): {motor.chave.decode()}")
    
    texto_secreto = "Esta é uma mensagem confidencial da atividade."
    print(f"\nTexto Original: {texto_secreto}")
    
    cifrado = motor.cifrar_mensagem(texto_secreto)
    print(f"\nTexto Cifrado (Ininteligível):\n{cifrado}")
    
    decifrado = motor.decifrar_mensagem(cifrado)
    print(f"\nTexto Decifrado (Original recuperado): {decifrado}")