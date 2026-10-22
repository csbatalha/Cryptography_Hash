import customtkinter as ctk
import hashlib
from motor_simetrico import CriptografiaSimetrica
from motor_assimetrico import CriptografiaAssimetrica

# Configuração visual do tema
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class AppSeguranca(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Projeto 1: Criptografia e Hash")
        self.geometry("850x650")

        # Instanciar os motores de criptografia criados nos passos anteriores
        self.motor_sim = CriptografiaSimetrica()
        self.motor_assi = CriptografiaAssimetrica()

        # Estrutura principal em abas (Tabview) com cantos arredondados
        self.tabview = ctk.CTkTabview(self, corner_radius=15)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)

        self.tab_sim = self.tabview.add("Criptografia Simétrica")
        self.tab_assi = self.tabview.add("Criptografia Assimétrica")
        self.tab_hash = self.tabview.add("Validação de Hash")

        self.construir_aba_simetrica()
        self.construir_aba_assimetrica()
        self.construir_aba_hash()

    # ==========================================
    # ABA 1: CRIPTOGRAFIA SIMÉTRICA
    # ==========================================
    def construir_aba_simetrica(self):
        frame = ctk.CTkFrame(self.tab_sim, corner_radius=10)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Mensagem Original:", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.input_sim = ctk.CTkEntry(frame, width=500)
        self.input_sim.pack(pady=10)

        ctk.CTkButton(frame, text="Cifrar (AES)", command=self.cifrar_sim).pack(pady=10)

        ctk.CTkLabel(frame, text="Mensagem Cifrada (Bytes):", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.saida_cifrada_sim = ctk.CTkTextbox(frame, width=500, height=80)
        self.saida_cifrada_sim.pack(pady=10)

        ctk.CTkButton(frame, text="Decifrar", command=self.decifrar_sim, fg_color="green", hover_color="darkgreen").pack(pady=10)

        ctk.CTkLabel(frame, text="Mensagem Decifrada:", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.saida_decifrada_sim = ctk.CTkEntry(frame, width=500)
        self.saida_decifrada_sim.pack(pady=10)

    def cifrar_sim(self):
        msg = self.input_sim.get()
        if msg:
            cifrado = self.motor_sim.cifrar_mensagem(msg)
            self.saida_cifrada_sim.delete("1.0", "end")
            self.saida_cifrada_sim.insert("1.0", cifrado.decode('utf-8'))
            self.saida_decifrada_sim.delete(0, "end")

    def decifrar_sim(self):
        cifrado_str = self.saida_cifrada_sim.get("1.0", "end-1c")
        if cifrado_str:
            decifrado = self.motor_sim.decifrar_mensagem(cifrado_str.encode('utf-8'))
            self.saida_decifrada_sim.delete(0, "end")
            self.saida_decifrada_sim.insert(0, decifrado)

    # ==========================================
    # ABA 2: CRIPTOGRAFIA ASSIMÉTRICA
    # ==========================================
    def construir_aba_assimetrica(self):
        # A estrutura visual é idêntica à simétrica, mas invoca o motor RSA
        frame = ctk.CTkFrame(self.tab_assi, corner_radius=10)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Mensagem Original:", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.input_assi = ctk.CTkEntry(frame, width=500)
        self.input_assi.pack(pady=10)

        ctk.CTkButton(frame, text="Cifrar com Chave Pública (RSA)", command=self.cifrar_assi).pack(pady=10)

        ctk.CTkLabel(frame, text="Mensagem Cifrada (Hexadecimal):", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.saida_cifrada_assi = ctk.CTkTextbox(frame, width=500, height=80)
        self.saida_cifrada_assi.pack(pady=10)

        ctk.CTkButton(frame, text="Decifrar com Chave Privada", command=self.decifrar_assi, fg_color="green", hover_color="darkgreen").pack(pady=10)

        ctk.CTkLabel(frame, text="Mensagem Decifrada:", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.saida_decifrada_assi = ctk.CTkEntry(frame, width=500)
        self.saida_decifrada_assi.pack(pady=10)

    def cifrar_assi(self):
        msg = self.input_assi.get()
        if msg:
            cifrado_bytes = self.motor_assi.cifrar_mensagem(msg)
            self.saida_cifrada_assi.delete("1.0", "end")
            self.saida_cifrada_assi.insert("1.0", cifrado_bytes.hex())
            self.saida_decifrada_assi.delete(0, "end")

    def decifrar_assi(self):
        cifrado_hex = self.saida_cifrada_assi.get("1.0", "end-1c")
        if cifrado_hex:
            cifrado_bytes = bytes.fromhex(cifrado_hex)
            decifrado = self.motor_assi.decifrar_mensagem(cifrado_bytes)
            self.saida_decifrada_assi.delete(0, "end")
            self.saida_decifrada_assi.insert(0, decifrado)

    # ==========================================
    # ABA 3: HASH (Validação de Integridade)
    # ==========================================
    def construir_aba_hash(self):
        # Bloco superior: Gerar Hash
        frame_gerar = ctk.CTkFrame(self.tab_hash, corner_radius=10)
        frame_gerar.pack(padx=20, pady=10, fill="x")

        ctk.CTkLabel(frame_gerar, text="1. Calcular Hash (SHA-256)", font=("Arial", 16, "bold")).pack(pady=10)
        self.input_hash = ctk.CTkEntry(frame_gerar, width=500, placeholder_text="Escreva a mensagem para gerar o hash...")
        self.input_hash.pack(pady=10)
        ctk.CTkButton(frame_gerar, text="Calcular Hash", command=self.calcular_hash).pack(pady=10)
        
        self.saida_hash_gerado = ctk.CTkEntry(frame_gerar, width=500)
        self.saida_hash_gerado.pack(pady=10)

        # Bloco inferior: Simular verificação com outra aplicação
        frame_verificar = ctk.CTkFrame(self.tab_hash, corner_radius=10)
        frame_verificar.pack(padx=20, pady=10, fill="x")

        ctk.CTkLabel(frame_verificar, text="2. Verificar Integridade", font=("Arial", 16, "bold")).pack(pady=10)
        self.input_comparar_texto = ctk.CTkEntry(frame_verificar, width=500, placeholder_text="Mensagem recebida...")
        self.input_comparar_texto.pack(pady=5)
        
        self.input_comparar_hash = ctk.CTkEntry(frame_verificar, width=500, placeholder_text="Cole o Hash recebido aqui para validar...")
        self.input_comparar_hash.pack(pady=5)

        ctk.CTkButton(frame_verificar, text="Validar Hash", command=self.validar_hash, fg_color="purple", hover_color="darkmagenta").pack(pady=10)
        
        self.lbl_resultado_hash = ctk.CTkLabel(frame_verificar, text="Aguardando validação...", font=("Arial", 14, "bold"))
        self.lbl_resultado_hash.pack(pady=10)

    def calcular_hash(self):
        msg = self.input_hash.get().encode('utf-8')
        hash_resultante = hashlib.sha256(msg).hexdigest()
        self.saida_hash_gerado.delete(0, "end")
        self.saida_hash_gerado.insert(0, hash_resultante)

    def validar_hash(self):
        msg_recebida = self.input_comparar_texto.get().encode('utf-8')
        hash_recebido = self.input_comparar_hash.get()
        
        hash_recalculado = hashlib.sha256(msg_recebida).hexdigest()
        
        if hash_recalculado == hash_recebido and hash_recebido != "":
            self.lbl_resultado_hash.configure(text="✅ SUCESSO: Os Hashes coincidem. Integridade garantida!", text_color="green")
        else:
            self.lbl_resultado_hash.configure(text="❌ ERRO: Os Hashes são diferentes. Arquivo corrompido!", text_color="red")

if __name__ == "__main__":
    app = AppSeguranca()
    app.mainloop()