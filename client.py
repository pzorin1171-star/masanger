import sys
import asyncio
import json
import logging
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTextEdit, QListWidget, QComboBox,
                             QLineEdit, QPushButton, QInputDialog, QMessageBox)
from PyQt6.QtCore import QUrl
from PyQt6.QtWebSockets import QWebSocket
from qasync import QEventLoop, asyncSlot

import key_manager
import crypto

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("client")

class ClientWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Анонимный мессенджер (WebSocket)")
        self.setGeometry(100, 100, 800, 600)

        self.private_key = key_manager.load_or_generate_keys()
        self.my_pubkey_der = key_manager.get_public_key_der(self.private_key)
        self.my_name = None
        self.server_url = None
        self.users = {}          # имя -> публичный ключ (DER)
        self.socket = QWebSocket()

        self.init_ui()
        # Используем QTimer для отложенного вызова после показа окна
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(0, self.ask_connection_details)

        # Подключаем сигналы сокета
        self.socket.textMessageReceived.connect(self.on_text_message)
        self.socket.errorOccurred.connect(self.on_socket_error)

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)

        bottom = QHBoxLayout()
        self.user_list = QListWidget()
        self.user_list.setMaximumWidth(200)
        bottom.addWidget(self.user_list)

        right = QVBoxLayout()
        self.recipient_combo = QComboBox()
        right.addWidget(self.recipient_combo)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Введите сообщение...")
        right.addWidget(self.message_input)

        self.send_button = QPushButton("Отправить")
        self.send_button.clicked.connect(self.send_message)
        right.addWidget(self.send_button)

        bottom.addLayout(right)
        layout.addLayout(bottom)

    def ask_connection_details(self):
        name, ok = QInputDialog.getText(self, "Имя", "Введите ваше имя:")
        if not ok or not name.strip():
            sys.exit()
        self.my_name = name.strip()

        url, ok = QInputDialog.getText(self, "Сервер",
                                       "URL сервера (например, ws://127.0.0.1:8080/ws):",
                                       text="ws://127.0.0.1:8080/ws")
        if not ok:
            sys.exit()
        self.server_url = url.strip()

        self.connect_to_server()

    def connect_to_server(self):
        self.socket.open(QUrl(self.server_url))
        self.log("Подключение к серверу...")

    def on_text_message(self, message):
        """Обработка входящих сообщений WebSocket"""
        try:
            data = json.loads(message)
            msg_type = data.get('type')

            if msg_type == 'new_user':
                name = data['name']
                pubkey_hex = data['pubkey_hex']
                if name != self.my_name and name not in self.users:
                    pubkey_der = bytes.fromhex(pubkey_hex)
                    self.users[name] = pubkey_der
                    self.recipient_combo.addItem(name)
                    self.user_list.addItem(name)
                    self.log(f"Новый пользователь: {name}")

            elif msg_type == 'message':
                encrypted_hex = data['encrypted']
                encrypted = bytes.fromhex(encrypted_hex)
                try:
                    decrypted = crypto.hybrid_decrypt(self.private_key, encrypted)
                    self.log(f"Получено: {decrypted.decode('utf-8')}")
                except Exception:
                    # сообщение не для нас или ошибка расшифровки
                    pass

        except Exception as e:
            self.log(f"Ошибка обработки сообщения: {e}")

    def on_socket_error(self, error):
        self.log(f"Ошибка WebSocket: {error}")
        QMessageBox.critical(self, "Ошибка", f"Не удалось подключиться: {error}")

    @asyncSlot()
    async def send_message(self):
        if self.socket.state() != QWebSocket.State.ConnectedState:
            self.log("Нет подключения к серверу")
            return
        recipient = self.recipient_combo.currentText()
        if recipient not in self.users:
            self.log("Выберите получателя из списка")
            return
        text = self.message_input.text().strip()
        if not text:
            return

        full_msg = f"{self.my_name}: {text}".encode('utf-8')
        pubkey = key_manager.get_public_key_from_der(self.users[recipient])
        encrypted = crypto.hybrid_encrypt(pubkey, full_msg)

        # Отправляем через WebSocket
        msg = json.dumps({
            'type': 'message',
            'encrypted': encrypted.hex()
        })
        self.socket.sendTextMessage(msg)

        self.message_input.clear()
        self.log(f"Вы -> {recipient}: {text}")

    def log(self, text):
        self.log_text.append(text)

def main():
    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    w = ClientWindow()
    w.show()

    with loop:
        loop.run_forever()

if __name__ == '__main__':
    main()
