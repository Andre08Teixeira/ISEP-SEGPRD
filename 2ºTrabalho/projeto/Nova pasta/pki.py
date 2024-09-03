import sys
import json
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QMessageBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class CertificateAuthority:
    def __init__(self):
        self.certificates = {}

    def issue_certificate(self, subject_name, validity_period):
        # Emite um certificado para o sujeito com o período de validade especificado
        private_key, public_key = generate_key_pair()
        certificate = {
            'subject': subject_name,
            'public_key': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'),
            'validity_period': validity_period
        }
        self.certificates[subject_name] = certificate
        return certificate

    def revoke_certificate(self, subject_name):
        # Revoga o certificado para o sujeito especificado
        if subject_name in self.certificates:
            del self.certificates[subject_name]
            QMessageBox.information(None, "Success", "Certificate for {} revoked.".format(subject_name))
        else:
            QMessageBox.critical(None, "Error", "Certificate not found for {}.".format(subject_name))

    def list_certificates(self):
        # Lista todos os certificados emitidos pela CA
        return self.certificates

class IdentityProvider:
    def __init__(self):
        self.user_identities = {}

    def generate_user_certificate(self, username):
        # Gera um par de chaves RSA para o utilizador
        private_key, public_key = generate_key_pair()

        # Emite um certificado para o utilizador
        certificate = {
            'username': username,
            'public_key': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        }
        self.user_identities[username] = (private_key, public_key)
        return certificate

    def revoke_user_certificate(self, username):
        # Revoga o certificado do utilizador
        if username in self.user_identities:
            del self.user_identities[username]
            QMessageBox.information(None, "Success", "Certificate for {} revoked.".format(username))
        else:
            QMessageBox.critical(None, "Error", "Certificate not found for {}.".format(username))

    def recover_user_identity(self, username):
        # Recupera a identidade do utilizador em caso de perda ou comprometimento
        if username in self.user_identities:
            return self.user_identities[username]
        else:
            return None

class EndToEndEncryption:
    def __init__(self):
        pass

    def encrypt_message(self, message, public_key):
        # Criptografa uma mensagem usando a chave pública do destinatário
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt_message(self, ciphertext, private_key):
        # Descriptografa uma mensagem usando a chave privada do destinatário
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

def generate_key_pair():
    # Gera um par de chaves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_certificates(ca):
    # Salva os certificados emitidos pela CA num arquivo JSON
    with open('certificates.json', 'w') as f:
        json.dump(ca.list_certificates(), f, indent=4)

def load_certificates():
    # Carrega os certificados emitidos pela CA a partir de um arquivo JSON
    try:
        with open('certificates.json', 'r') as f:
            certificates = json.load(f)
        return certificates
    except FileNotFoundError:
        return {}

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Certificate Authority")
        self.ca = CertificateAuthority()
        self.identity_provider = IdentityProvider()
        self.end_to_end_encryption = EndToEndEncryption()
        self.initUI()

    def initUI(self):
        # Cria os widgets na janela
        self.subject_label = QLabel("Subject Name:", self)
        self.subject_label.move(20, 20)
        self.subject_entry = QLineEdit(self)
        self.subject_entry.move(150, 20)

        self.validity_label = QLabel("Validity Period:", self)
        self.validity_label.move(20, 50)
        self.validity_entry = QLineEdit(self)
        self.validity_entry.move(150, 50)

        self.issue_ca_button = QPushButton("Issue CA Certificate", self)
        self.issue_ca_button.clicked.connect(self.issue_ca_certificate)
        self.issue_ca_button.move(20, 80)

        self.revoke_ca_button = QPushButton("Revoke CA Certificate", self)
        self.revoke_ca_button.clicked.connect(self.revoke_ca_certificate)
        self.revoke_ca_button.move(150, 80)

        self.list_ca_button = QPushButton("List CA Certificates", self)
        self.list_ca_button.clicked.connect(self.list_ca_certificates)
        self.list_ca_button.move(280, 80)

        self.issue_user_button = QPushButton("Issue User Certificate", self)
        self.issue_user_button.clicked.connect(self.issue_user_certificate)
        self.issue_user_button.move(20, 120)

        self.revoke_user_button = QPushButton("Revoke User Certificate", self)
        self.revoke_user_button.clicked.connect(self.revoke_user_certificate)
        self.revoke_user_button.move(150, 120)

        self.list_user_button = QPushButton("List User Certificates", self)
        self.list_user_button.clicked.connect(self.list_user_certificates)
        self.list_user_button.move(280, 120)

        self.encrypt_button = QPushButton("Encrypt Message", self)
        self.encrypt_button.clicked.connect(self.encrypt_message)
        self.encrypt_button.move(20, 160)

        self.decrypt_button = QPushButton("Decrypt Message", self)
        self.decrypt_button.clicked.connect(self.decrypt_message)
        self.decrypt_button.move(150, 160)

        # Configura o tamanho da janela
        self.setGeometry(100, 100, 400, 220)

    def issue_ca_certificate(self):
        # Emite um certificado para a Autoridade de Certificação (CA)
        subject_name = self.subject_entry.text()
        validity_period = self.validity_entry.text()
        certificate = self.ca.issue_certificate(subject_name, validity_period)
        save_certificates(self.ca)
        QMessageBox.information(self, "Success", "CA Certificate issued for {}.".format(subject_name))

    def revoke_ca_certificate(self):
        # Revoga o certificado da Autoridade de Certificação (CA)
        subject_name = self.subject_entry.text()
        self.ca.revoke_certificate(subject_name)
        save_certificates(self.ca)

    def list_ca_certificates(self):
        # Lista os certificados emitidos pela Autoridade de Certificação (CA)
        certificates = self.ca.list_certificates()
        QMessageBox.information(self, "CA Certificates", json.dumps(certificates, indent=4))

    def issue_user_certificate(self):
        # Emite um certificado para o utilizador
        username = self.subject_entry.text()
        certificate = self.identity_provider.generate_user_certificate(username)
        QMessageBox.information(self, "Success", "User Certificate issued for {}.".format(username))

    def revoke_user_certificate(self):
        # Revoga o certificado do utilizador
        username = self.subject_entry.text()
        self.identity_provider.revoke_user_certificate(username)

    def list_user_certificates(self):
        # Lista os certificados emitidos para utilizadores
        user_certificates = {}
        for username, (private_key, public_key) in self.identity_provider.user_identities.items():
            user_certificates[username] = {
                'public_key': public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
            }
        QMessageBox.information(self, "User Certificates", json.dumps(user_certificates, indent=4))

    def encrypt_message(self):
        # Criptografa uma mensagem usando a chave pública do destinatário
        recipient = self.subject_entry.text()
        message = self.validity_entry.text()
        if recipient in self.identity_provider.user_identities:
            recipient_public_key = self.identity_provider.user_identities[recipient][1]
            ciphertext = self.end_to_end_encryption.encrypt_message(message, recipient_public_key)
            QMessageBox.information(self, "Success", "Message encrypted successfully.")
        else:
            QMessageBox.critical(self, "Error", "Recipient not found.")

    def decrypt_message(self):
        # Descriptografa uma mensagem usando a chave privada do destinatário
        recipient = self.subject_entry.text()
        ciphertext = self.validity_entry.text()
        if recipient in self.identity_provider.user_identities:
            recipient_private_key = self.identity_provider.user_identities[recipient][0]
            plaintext = self.end_to_end_encryption.decrypt_message(ciphertext, recipient_private_key)
            QMessageBox.information(self, "Success", "Decrypted Message: {}".format(plaintext))
        else:
            QMessageBox.critical(self, "Error", "Recipient not found.")

if __name__ == '__main__':
    # Inicia a aplicação PyQt
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())