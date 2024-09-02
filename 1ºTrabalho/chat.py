import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QTextEdit, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
import socks
import socket
import threading
import rsa

class ChatWindow(QWidget):
    def __init__(self, parent=None):
        super(ChatWindow, self).__init__(parent)
        self.setWindowTitle("ISEP Chat")
        self.resize(800, 600)  # Ajustar o tamanho conforme necessário

        self.setup_ui()

        self.public_key, self.private_key = rsa.newkeys(1024)
        self.public_partner = None

    def setup_ui(self):
        layout = QVBoxLayout()

        # Texto de saída
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("QTextEdit { background-color: #f0f0f0; color: #333; border: 1px solid #ccc; }")
        layout.addWidget(self.output_text)

        # Caixa de entrada de texto
        self.input_text = QLineEdit()
        self.input_text.setFixedHeight(60)
        self.input_text.setPlaceholderText("Digite a mensagem aqui")
        self.input_text.setStyleSheet("QLineEdit { background-color: #fff; color: #333; border: 1px solid #ccc; }")
        self.input_text.returnPressed.connect(self.send_message)  # Conectar a tecla Enter à função send_message
        layout.addWidget(self.input_text)

        # Botão de enviar mensagem
        self.send_button = QPushButton("Enviar")
        self.send_button.setStyleSheet("QPushButton { background-color: #06bd33; color: #fff; border: none; padding: 8px 20px; }"
                                       "QPushButton:hover { background-color: #038222; }")
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)

        # Botão para iniciar o servidor
        self.host_button = QPushButton("Iniciar Servidor")
        self.host_button.setStyleSheet("QPushButton { background-color: #0465ba; color: #fff; border: none; padding: 8px 20px; }"
                                       "QPushButton:hover { background-color: #014682; }")
        self.host_button.clicked.connect(self.run_server)
        layout.addWidget(self.host_button)

        # Botão para conectar como cliente
        self.connect_button = QPushButton("Conectar como Cliente")
        self.connect_button.setStyleSheet("QPushButton { background-color: #c4a704; color: #fff; border: none; padding: 8px 20px; }"
                                       "QPushButton:hover { background-color: #8a7503; }")
        self.connect_button.clicked.connect(self.run_client)
        layout.addWidget(self.connect_button)

        self.setLayout(layout)

    def configure_tor_connection(self):
        try:
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            self.output_text.append("Conexão ao Tor estabelecida com sucesso.")
        except Exception as e:
            self.output_text.append("Erro ao conectar ao Tor: " + str(e))

    def send_message(self):
        message = self.input_text.text()
        if message:  # Enviar apenas se a mensagem não estiver vazia
            self.input_text.clear()
            self.output_text.append("Eu: " + message)
            self.client.send(rsa.encrypt(message.encode(), self.public_partner))

    def receive_messages(self):
        while True:
            try:
                received_message = rsa.decrypt(self.client.recv(4096), self.private_key).decode()
                self.output_text.append("Amigo: " + received_message)
            except Exception as e:
                print("Erro ao receber mensagem:", e)
                break

    def run_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("localhost", 9999))
        self.server.listen()

        self.client, _ = self.server.accept()
        self.client.send(self.public_key.save_pkcs1("PEM"))
        self.public_partner = rsa.PublicKey.load_pkcs1(self.client.recv(1024))

        self.configure_tor_connection()

        threading.Thread(target=self.receive_messages).start()

    def run_client(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(("4.tcp.eu.ngrok.io", 10718))  # Alterar para o endereço do servidor desejado

        self.public_partner = rsa.PublicKey.load_pkcs1(self.client.recv(1024))
        self.client.send(self.public_key.save_pkcs1("PEM"))

        self.configure_tor_connection()

        threading.Thread(target=self.receive_messages).start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Define o ícone da janela
    app.setWindowIcon(QIcon("isep.png")) 
    window = ChatWindow()
    window.show()
    sys.exit(app.exec_())
