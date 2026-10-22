from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

class GeradorCertificado:
    def __init__(self, nome_titular="Aluno Seguranca Informacao"):
        self.nome_titular = nome_titular

    def gerar_identidade(self):
        print("A gerar o par de chaves RSA de 2048 bits...")
        # 1. Gerar Chave Privada
        chave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # 2. Construir os dados do Certificado (Subject e Issuer)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Sao Paulo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Cubatao"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IFSP"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.nome_titular),
        ])

        print("A construir o Certificado Digital X.509...")
        # 3. Montar e Assinar o Certificado (Autoassinado)
        certificado = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            chave_privada.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            # Certificado válido por 1 ano
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).sign(chave_privada, hashes.SHA256())

        self._guardar_ficheiros(chave_privada, certificado)
        print("✅ Identidade criptográfica gerada com sucesso!")

    def _guardar_ficheiros(self, chave_privada, certificado):
        # Guardar a Chave Privada
        with open("chave_privada.pem", "wb") as f:
            f.write(chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Guardar o Certificado Digital (que contém a Chave Pública)
        with open("certificado.pem", "wb") as f:
            f.write(certificado.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    gerador = GeradorCertificado()
    gerador.gerar_identidade()