import sys
import asyncio
import logging
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTextEdit, QListWidget, QComboBox,
                             QLineEdit, QPushButton, QCheckBox, QInputDialog,
                             QMessageBox)
from PyQt6.QtCore import Qt, QTimer
from qasync import QEventLoop, asyncSlot

import key_manager
import crypto
import tor_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("client")

class ClientWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Анонимный мессенджер")
        self.setGeometry(100, 100, 800, 600)

        self.private_key = key_manager.load_or_generate_keys()
        self.my_pubkey_der = key_manager.get_public_key_der(self.private_key)
        self.my_name = None
        self.server_host = None
        self.server_port = None
        self.users = {}          # имя -> публичный ключ (DER)
        self.reader = None
        self.writer = None
        self.use_tor = False

        self.init_ui()
        QTimer.singleShot(0, self.ask_connection_details)

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

        self.tor_checkbox = QCheckBox("Использовать Tor (localhost:9050)")
        self.tor_checkbox.stateChanged.connect(self.toggle_tor)
        right.addWidget(self.tor_checkbox)

        bottom.addLayout(right)
        layout.addLayout(bottom)

    def toggle_tor(self, state):
        self.use_tor = (state == Qt.CheckState.Checked.value)

    def ask_connection_details(self):
        name, ok = QInputDialog.getText(self, "Имя", "Введите ваше имя:")
        if not ok or not name.strip():
            sys.exit()
        self.my_name = name.strip()

        addr, ok = QInputDialog.getText(self, "Сервер",
                                        "Адрес сервера (host:port):",
                                        text="127.0.0.1:8888")
        if not ok:
            sys.exit()
        try:
            host, port_str = addr.strip().split(':')
            self.server_host = host
            self.server_port = int(port_str)
        except Exception:
            QMessageBox.critical(self, "Ошибка", "Неверный формат адреса")
            sys.exit()

        asyncio.create_task(self.connect_to_server())

    async def connect_to_server(self):
        try:
            if self.use_tor:
                self.reader, self.writer = await tor_manager.open_tor_connection(
                    self.server_host, self.server_port
                )
            else:
                self.reader, self.writer = await asyncio.open_connection(
                    self.server_host, self.server_port
                )

            # Регистрация
            name_bytes = self.my_name.encode('utf-8')
            self.writer.write(len(name_bytes).to_bytes(4, 'big'))
            self.writer.write(name_bytes)
            self.writer.write(len(self.my_pubkey_der).to_bytes(4, 'big'))
            self.writer.write(self.my_pubkey_der)
            await self.writer.drain()

            asyncio.create_task(self.receive_messages())
            self.log("Подключено к серверу")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось подключиться: {e}")
            sys.exit()

    async def receive_messages(self):
        try:
            while True:
                data = await self.reader.readexactly(4)
                msg_len = int.from_bytes(data, 'big')
                msg = await self.reader.readexactly(msg_len)
                await self.handle_server_message(msg)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            self.log("Соединение потеряно")
            # Здесь можно добавить переподключение

    async def handle_server_message(self, msg):
        if not msg:
            return
        msg_type = msg[0]
        if msg_type == 0x01:          # новый пользователь
            name_len = int.from_bytes(msg[1:5], 'big')
            name = msg[5:5+name_len].decode('utf-8')
            key_len = int.from_bytes(msg[5+name_len:5+name_len+4], 'big')
            pubkey_der = msg[5+name_len+4:5+name_len+4+key_len]

            if name != self.my_name and name not in self.users:
                self.users[name] = pubkey_der
                self.recipient_combo.addItem(name)
                self.user_list.addItem(name)
                self.log(f"Новый пользователь: {name}")

        elif msg_type == 0x02:          # сообщение
            encrypted = msg[1:]
            try:
                decrypted = crypto.hybrid_decrypt(self.private_key, encrypted)
                self.log(f"Получено: {decrypted.decode('utf-8')}")
            except Exception:
                # сообщение не для нас
                pass

    @asyncSlot()
    async def send_message(self):
        if not self.writer:
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

        self.writer.write(len(encrypted).to_bytes(4, 'big'))
        self.writer.write(encrypted)
        await self.writer.drain()

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
