import sys
import json
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes
from pki import CertificateAuthority

class User:
    def __init__(self, username):
        self.username = username
        self.private_key, self.public_key = self.generate_key_pair()

    def generate_key_pair(self):
        # Gera um par de chaves RSA para o utilizador
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_message(self, message):
        # Assina uma mensagem usando a chave privada do utilizador
        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return signature

    def verify_signature(self, message, signature, public_key):
        # Verifica a assinatura de uma mensagem usando a chave pública do remetente
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hashes.SHA256())
            )
            return True
        except:
            return False

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Messaging App")
        self.users = {}
        self.current_user = None
        self.load_users()  # Carrega os utilizadores existentes do arquivo JSON
        self.initUI()
        self.ca = CertificateAuthority()

    def initUI(self):
        layout = QVBoxLayout()

        # Label e campo de entrada para nome de utilizador
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_entry)
        layout.addLayout(username_layout)

        # Botão para fazer login ou criar conta
        login_button = QPushButton("Login / Create Account")
        login_button.clicked.connect(self.login_or_create_account)
        layout.addWidget(login_button)

        # Campo de entrada para mensagem
        self.message_entry = QLineEdit()
        layout.addWidget(self.message_entry)

        # Botão para enviar mensagem
        send_button = QPushButton("Send")
        send_button.clicked.connect(self.send_message)
        layout.addWidget(send_button)

        # Área de texto para exibir mensagens
        self.messages_text = QTextEdit()
        self.messages_text.setReadOnly(True)
        layout.addWidget(self.messages_text)

        self.setLayout(layout)

    def login_or_create_account(self):
       # Verifica se o utilizador já existe, caso contrário, cria uma nova conta
        username = self.username_entry.text()
        if username in self.users:
            # Verificar se o certificado do utilizador é válido
            if self.ca.verify_certificate(username):
                self.current_user = self.users[username]
                QMessageBox.information(self, "Success", "Logged in as {}.".format(username))
            else:
                QMessageBox.critical(self, "Error", "Invalid certificate for {}.".format(username))
        else:
            # Emitir um certificado para o novo utilizador
            certificate = self.ca.issue_certificate(username, 10)
            if certificate:
                new_user = User(username)
                self.users[username] = new_user
                self.current_user = new_user
                self.save_users()  # Salva os novos dados de login
                QMessageBox.information(self, "Success", "Account created for {}.".format(username))
            else:
                QMessageBox.critical(self, "Error", "Failed to issue certificate for {}.".format(username))

    def send_message(self):
        # Envia uma mensagem assinada pelo utilizador atual
        if self.current_user:
            message = self.message_entry.text()
            signature = self.current_user.sign_message(message)
            self.messages_text.append("Sent: {}".format(message))
            self.messages_text.append("Signature: {}".format(signature.hex()))
            self.message_entry.clear()
        else:
            QMessageBox.critical(self, "Error", "No user logged in.")

    def save_users(self):
        # Guarda os dados de login dos utilizador num arquivo JSON
        with open('users.json', 'w') as f:
            user_data = {user.username: {"private_key": user.private_key.private_bytes(
                                            encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption()
                                        ).decode('utf-8'),
                                        "public_key": user.public_key.public_bytes(
                                            encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                                        ).decode('utf-8')} for user in self.users.values()}
            json.dump(user_data, f, indent=4)

    def load_users(self):
        # Carrega os dados de login dos utilizadores do arquivo JSON
        try:
            with open('users.json', 'r') as f:
                user_data = json.load(f)
            for username, keys in user_data.items():
                private_key = serialization.load_pem_private_key(
                    keys["private_key"].encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                public_key = serialization.load_pem_public_key(
                    keys["public_key"].encode('utf-8'),
                    backend=default_backend()
                )
                self.users[username] = User(username)
                self.users[username].private_key = private_key
                self.users[username].public_key = public_key
        except FileNotFoundError:
            pass

if __name__ == '__main__':
    # Inicia a aplicação PyQt
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())