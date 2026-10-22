import customtkinter as ctk
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

# Configuração visual do tema
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class AppAssinatura(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Projeto 2: Assinatura Digital e Certificados")
        self.geometry("850x650")

        # Estrutura principal em abas
        self.tabview = ctk.CTkTabview(self, corner_radius=15)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)

        self.tab_assinar = self.tabview.add("1. Assinar Documento")
        self.tab_verificar = self.tabview.add("2. Verificar Assinatura")

        self.construir_aba_assinar()
        self.construir_aba_verificar()

    def carregar_chave_privada(self):
        """Lê o ficheiro .pem gerado na Fase 1 para assinar."""
        try:
            with open("chave_privada.pem", "rb") as key_file:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
        except FileNotFoundError:
            return None

    def carregar_certificado(self):
        """Lê o ficheiro .pem do certificado gerado na Fase 1 para extrair a Chave Pública."""
        try:
            with open("certificado.pem", "rb") as cert_file:
                return x509.load_pem_x509_certificate(cert_file.read())
        except FileNotFoundError:
            return None

    # ==========================================
    # ABA 1: ASSINAR DOCUMENTO
    # ==========================================
    def construir_aba_assinar(self):
        frame = ctk.CTkFrame(self.tab_assinar, corner_radius=10)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Conteúdo do Documento a Assinar:", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.input_doc_assinar = ctk.CTkTextbox(frame, width=600, height=100)
        self.input_doc_assinar.pack(pady=10)

        ctk.CTkButton(frame, text="Assinar com Chave Privada", command=self.assinar_documento).pack(pady=10)

        ctk.CTkLabel(frame, text="Assinatura Digital Gerada (Hexadecimal):", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.saida_assinatura = ctk.CTkTextbox(frame, width=600, height=120)
        self.saida_assinatura.pack(pady=10)

    def assinar_documento(self):
        documento = self.input_doc_assinar.get("1.0", "end-1c").encode('utf-8')
        chave_privada = self.carregar_chave_privada()

        if not chave_privada:
            self.saida_assinatura.delete("1.0", "end")
            self.saida_assinatura.insert("1.0", "ERRO: Ficheiro 'chave_privada.pem' não encontrado.")
            return

        if documento:
            # O processo de assinatura envolve aplicar o Hash SHA-256 e cifrar com a Chave Privada
            assinatura = chave_privada.sign(
                documento,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.saida_assinatura.delete("1.0", "end")
            self.saida_assinatura.insert("1.0", assinatura.hex())

    # ==========================================
    # ABA 2: VERIFICAR ASSINATURA
    # ==========================================
    def construir_aba_verificar(self):
        frame = ctk.CTkFrame(self.tab_verificar, corner_radius=10)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Conteúdo do Documento Recebido:", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.input_doc_verificar = ctk.CTkTextbox(frame, width=600, height=100)
        self.input_doc_verificar.pack(pady=10)

        ctk.CTkLabel(frame, text="Colar Assinatura Digital Recebida:", font=("Arial", 14, "bold")).pack(pady=(10, 0))
        self.input_assinatura_verificar = ctk.CTkTextbox(frame, width=600, height=120)
        self.input_assinatura_verificar.pack(pady=10)

        ctk.CTkButton(frame, text="Verificar com Certificado Digital (Chave Pública)", command=self.verificar_assinatura, fg_color="purple", hover_color="darkmagenta").pack(pady=10)

        self.lbl_resultado_assinatura = ctk.CTkLabel(frame, text="Aguardando validação...", font=("Arial", 14, "bold"))
        self.lbl_resultado_assinatura.pack(pady=10)

    def verificar_assinatura(self):
        documento = self.input_doc_verificar.get("1.0", "end-1c").encode('utf-8')
        assinatura_hex = self.input_assinatura_verificar.get("1.0", "end-1c").strip()
        certificado = self.carregar_certificado()

        if not certificado:
            self.lbl_resultado_assinatura.configure(text="ERRO: Ficheiro 'certificado.pem' não encontrado.", text_color="orange")
            return

        try:
            assinatura_bytes = bytes.fromhex(assinatura_hex)
            chave_publica = certificado.public_key()
            
            # Tenta verificar a assinatura. Se falhar, levanta uma exceção.
            chave_publica.verify(
                assinatura_bytes,
                documento,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.lbl_resultado_assinatura.configure(text="✅ SUCESSO: Assinatura Válida! O autor é autêntico e o texto não foi alterado.", text_color="green")
        except Exception:
            self.lbl_resultado_assinatura.configure(text="❌ ERRO: Assinatura Inválida! Documento adulterado ou autor não reconhecido.", text_color="red")

if __name__ == "__main__":
    app = AppAssinatura()
    app.mainloop()