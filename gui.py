import sys
import json
import time
from PyQt6.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTextEdit, QLabel, QLineEdit, QFileDialog, QMessageBox, QSpinBox, QDialog, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor
from knapsack_cipher import KnapsackCipher, KnapsackPublicKey, KnapsackPrivateKey

# Импорт для графиков
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


class BinaryRepresentationDialog(QDialog):
    def __init__(self, binary_info, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Бинарное представление")
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.resize(600, 400)
        
        layout = QVBoxLayout()
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setPlainText(binary_info)
        layout.addWidget(self.text_edit)
        
        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)
        
        self.setLayout(layout)


class PlotCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.ax = fig.add_subplot(111)
        super().__init__(fig)
        self.setParent(parent)

    def plot(self, x_data, y_data):
        self.ax.clear()
        self.ax.plot(x_data, y_data, marker='o', linestyle='-')
        self.ax.set_title("Время генерации ключей и Размер рюкзака")
        self.ax.set_xlabel("Размер рюкзака (n)")
        self.ax.set_ylabel("Время генерации (сек)")
        self.ax.tick_params(axis='both', which='major', labelsize=16)
        self.ax.grid(True)
        self.draw()


class KnapsackGUI(QWidget):
    def __init__(self):
        self.time_table = None
        super().__init__()
        self.cipher = KnapsackCipher()
        self.setWindowTitle("0-2 Мультипликативная Рюкзачная Криптосистема")
        self.setGeometry(200, 200, 900, 650)
        
        self.tabs = QTabWidget()
        self.tab_generate = QWidget()
        self.tab_encrypt = QWidget()
        self.tab_decrypt = QWidget()
        self.tab_plot = QWidget()
        
        self.tabs.addTab(self.tab_generate, "Генерация ключей")
        self.tabs.addTab(self.tab_encrypt, "Шифрование")
        self.tabs.addTab(self.tab_decrypt, "Расшифрование")
        self.tabs.addTab(self.tab_plot, "График")
        
        self.init_generate_tab()
        self.init_encrypt_tab()
        self.init_decrypt_tab()
        self.init_plot_tab()
        
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        # Для хранения данных графика
        self.plot_n_values = []
        self.plot_times = []
        self.last_binary_info = ""

    # ------------------ Вкладка генерации ключей ------------------
    def init_generate_tab(self):
        layout = QVBoxLayout()
        
        hlayout = QHBoxLayout()
        hlayout.addWidget(QLabel("Размер рюкзака (n):"))
        self.size_spin = QSpinBox()
        self.size_spin.setMinimum(3)
        self.size_spin.setMaximum(200)
        self.size_spin.setValue(60)
        hlayout.addWidget(self.size_spin)

        hlayout.addWidget(QLabel("Минимальная битовая длина простых:"))
        self.bits_spin = QSpinBox()
        self.bits_spin.setMinimum(4)
        self.bits_spin.setMaximum(64)
        self.bits_spin.setValue(32)
        hlayout.addWidget(self.bits_spin)

        layout.addLayout(hlayout)

        self.generate_button = QPushButton("Сгенерировать ключи")
        self.generate_button.clicked.connect(self.generate_keys)
        layout.addWidget(self.generate_button)

        self.gen_time_label = QLabel("")
        layout.addWidget(self.gen_time_label)

        self.gen_output = QTextEdit()
        self.gen_output.setReadOnly(True)
        layout.addWidget(self.gen_output)

        self.tab_generate.setLayout(layout)

    def generate_keys(self):
        n = self.size_spin.value()
        bits = self.bits_spin.value()
        self.gen_output.append(f"Генерация ключей с n={n}, bits={bits}...")
        start_time = time.perf_counter()
        try:
            pub_key, priv_key = self.cipher.generate_keys(n=n, min_bits=bits)
            pub_key.save("public.key")
            priv_key.save("private.key")
            elapsed = time.perf_counter() - start_time
            self.gen_output.append("Ключи успешно сгенерированы и сохранены.\n")
            self.gen_time_label.setText(f"Время генерации ключей: {elapsed:.3f} сек.")
        except Exception as e:
            self.gen_output.append(f"Ошибка: {e}\n")
            self.gen_time_label.setText("")

    # ------------------ Вкладка шифрования ------------------
    def init_encrypt_tab(self):
        layout = QVBoxLayout()
        
        self.encrypt_input = QTextEdit()
        self.encrypt_input.setPlaceholderText("Введите сообщение для шифрования...")
        layout.addWidget(self.encrypt_input)

        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("Файл открытого ключа:"))
        self.pubkey_enc_path = QLineEdit("public.key")
        h_layout.addWidget(self.pubkey_enc_path)
        self.pubkey_enc_browse = QPushButton("Обзор")
        self.pubkey_enc_browse.clicked.connect(self.browse_pubkey_enc)
        h_layout.addWidget(self.pubkey_enc_browse)
        layout.addLayout(h_layout)

        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Зашифровать")
        self.encrypt_button.clicked.connect(self.encrypt_message)
        button_layout.addWidget(self.encrypt_button)

        self.show_binary_button = QPushButton("Показать бинарное представление")
        self.show_binary_button.clicked.connect(self.show_binary_info)
        self.show_binary_button.setEnabled(False)
        button_layout.addWidget(self.show_binary_button)
        layout.addLayout(button_layout)

        self.enc_time_label = QLabel("")
        layout.addWidget(self.enc_time_label)

        self.encrypt_output = QTextEdit()
        self.encrypt_output.setReadOnly(True)
        layout.addWidget(self.encrypt_output)

        self.tab_encrypt.setLayout(layout)

    def browse_pubkey_enc(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл открытого ключа", "", "Key Files (*.key);;All Files (*)")
        if path:
            self.pubkey_enc_path.setText(path)

    def encrypt_message(self):
        message = self.encrypt_input.toPlainText()
        pubkey_file = self.pubkey_enc_path.text()
        if not message:
            QMessageBox.warning(self, "Ошибка", "Введите сообщение для шифрования.")
            return
        try:
            pub_key = KnapsackPublicKey.load(pubkey_file)
            start_time = time.perf_counter()
            encrypted_list = self.cipher.encrypt(message, pub_key)
            elapsed = time.perf_counter() - start_time
            json_str = json.dumps(encrypted_list, indent=4)
            self.encrypt_output.setPlainText(json_str)
            self.enc_time_label.setText(f"Время шифрования: {elapsed:.3f} сек.")
            
            # Сохраняем информацию о бинарном представлении
            self.last_binary_info = self._get_binary_info(message, pub_key)
            self.show_binary_button.setEnabled(True)
        except FileNotFoundError:
            QMessageBox.critical(self, "Ошибка", f"Файл '{pubkey_file}' не найден.")
            self.enc_time_label.setText("")
            self.show_binary_button.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка шифрования:\n{e}")
            self.enc_time_label.setText("")
            self.show_binary_button.setEnabled(False)

    def _get_binary_info(self, message: str, pub_key: KnapsackPublicKey) -> str:
        """Генерирует информацию о бинарном представлении сообщения."""
        try:
            chunks = self.cipher._text_to_chunks(message, pub_key.n)
            info = "=== Бинарное представление входного текста ===\n\n"
            
            # Получаем байты исходного сообщения
            message_bytes = message.encode('utf-8')
            info += f"Исходное сообщение в байтах (UTF-8):\n{message_bytes}\n\n"
            
            # Показываем бинарное представление каждого байта
            info += "Бинарное представление каждого байта:\n"
            for byte in message_bytes:
                info += f"{byte:3d} = {format(byte, '08b')}\n"
            
            # Информация о разбиении на блоки
            info += f"\nСообщение разбито на {len(chunks)} блок(ов) по {pub_key.n} элементов\n"
            
            # Показываем троичные векторы для каждого блока
            info += "\nТроичные векторы для каждого блока:\n"
            for i, chunk in enumerate(chunks, 1):
                info += f"Блок {i}: {chunk}\n"
            
            return info
        except Exception as e:
            return f"Ошибка при генерации бинарного представления: {str(e)}"

    def show_binary_info(self):
        """Показывает диалоговое окно с бинарным представлением."""
        if not self.last_binary_info:
            QMessageBox.warning(self, "Ошибка", "Нет информации о бинарном представлении.")
            return
            
        dialog = BinaryRepresentationDialog(self.last_binary_info, self)
        dialog.exec()

    # ------------------ Вкладка расшифровки ------------------
    def init_decrypt_tab(self):
        layout = QVBoxLayout()

        self.decrypt_input = QTextEdit()
        self.decrypt_input.setPlaceholderText("Вставьте шифртекст...")
        layout.addWidget(self.decrypt_input)

        h_layout1 = QHBoxLayout()
        h_layout1.addWidget(QLabel("Файл открытого ключа:"))
        self.pubkey_dec_path = QLineEdit("public.key")
        h_layout1.addWidget(self.pubkey_dec_path)
        self.pubkey_dec_browse = QPushButton("Обзор")
        self.pubkey_dec_browse.clicked.connect(self.browse_pubkey_dec)
        h_layout1.addWidget(self.pubkey_dec_browse)
        layout.addLayout(h_layout1)

        h_layout2 = QHBoxLayout()
        h_layout2.addWidget(QLabel("Файл закрытого ключа:"))
        self.privkey_dec_path = QLineEdit("private.key")
        h_layout2.addWidget(self.privkey_dec_path)
        self.privkey_dec_browse = QPushButton("Обзор")
        self.privkey_dec_browse.clicked.connect(self.browse_privkey_dec)
        h_layout2.addWidget(self.privkey_dec_browse)
        layout.addLayout(h_layout2)

        self.decrypt_button = QPushButton("Расшифровать")
        self.decrypt_button.clicked.connect(self.decrypt_message)
        layout.addWidget(self.decrypt_button)

        self.dec_time_label = QLabel("")
        layout.addWidget(self.dec_time_label)

        self.decrypt_output = QTextEdit()
        self.decrypt_output.setReadOnly(True)
        layout.addWidget(self.decrypt_output)

        self.tab_decrypt.setLayout(layout)

    def browse_pubkey_dec(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл открытого ключа", "", "Key Files (*.key);;All Files (*)")
        if path:
            self.pubkey_dec_path.setText(path)

    def browse_privkey_dec(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл закрытого ключа", "", "Key Files (*.key);;All Files (*)")
        if path:
            self.privkey_dec_path.setText(path)

    def decrypt_message(self):
        ciphertext_json = self.decrypt_input.toPlainText()
        pubkey_file = self.pubkey_dec_path.text()
        privkey_file = self.privkey_dec_path.text()

        if not ciphertext_json.strip():
            QMessageBox.warning(self, "Ошибка", "Введите шифртекст для расшифровки.")
            return

        try:
            pub_key = KnapsackPublicKey.load(pubkey_file)
            priv_key = KnapsackPrivateKey.load(privkey_file)
            ciphertext_list = json.loads(ciphertext_json)
            start_time = time.perf_counter()
            decrypted_text = self.cipher.decrypt(ciphertext_list, priv_key, pub_key)
            elapsed = time.perf_counter() - start_time
            self.decrypt_output.setPlainText(decrypted_text)
            self.dec_time_label.setText(f"Время расшифровки: {elapsed:.3f} сек.")
        except FileNotFoundError:
            QMessageBox.critical(self, "Ошибка", "Один из файлов ключей не найден.")
            self.dec_time_label.setText("")
        except json.JSONDecodeError:
            QMessageBox.critical(self, "Ошибка", "Шифртекст имеет неверный JSON формат.")
            self.dec_time_label.setText("")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка при расшифровке:\n{e}")
            self.dec_time_label.setText("")

    # ------------------ Вкладка графика ------------------
    def init_plot_tab(self):
        layout = QVBoxLayout()

        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("Минимальный размер рюкзака (n):"))
        self.plot_n_min = QSpinBox()
        self.plot_n_min.setMinimum(10)
        self.plot_n_min.setMaximum(200)
        self.plot_n_min.setValue(10)
        h_layout.addWidget(self.plot_n_min)

        h_layout.addWidget(QLabel("Максимальный размер рюкзака (n):"))
        self.plot_n_max = QSpinBox()
        self.plot_n_max.setMinimum(10)
        self.plot_n_max.setMaximum(200)
        self.plot_n_max.setValue(100)
        h_layout.addWidget(self.plot_n_max)

        h_layout.addWidget(QLabel("Шаг:"))
        self.plot_n_step = QSpinBox()
        self.plot_n_step.setMinimum(1)
        self.plot_n_step.setMaximum(50)
        self.plot_n_step.setValue(10)
        h_layout.addWidget(self.plot_n_step)

        layout.addLayout(h_layout)

        self.plot_button = QPushButton("Построить график")
        self.plot_button.clicked.connect(self.plot_graph)
        layout.addWidget(self.plot_button)

        self.time_table = QTableWidget()
        self.time_table.setColumnCount(2)
        self.time_table.setHorizontalHeaderLabels(["Размер рюкзака (n)", "Время генерации (сек)"])
        self.time_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.time_table)

        self.plot_canvas = PlotCanvas(self, width=8, height=5)
        layout.addWidget(self.plot_canvas)

        self.plot_status_label = QLabel("")
        layout.addWidget(self.plot_status_label)

        self.tab_plot.setLayout(layout)

    def plot_graph(self):
        n_min = self.plot_n_min.value()
        n_max = self.plot_n_max.value()
        step = self.plot_n_step.value()

        if n_min > n_max:
            QMessageBox.warning(self, "Ошибка", "Минимальный размер не может быть больше максимального.")
            return
        
        self.plot_status_label.setText("Запуск серии замеров, подождите...")
        QApplication.processEvents()  # чтобы UI обновился

        times = []
        ns = []
        bits = self.bits_spin.value()

        self.time_table.setRowCount(0)

        for n in range(n_min, n_max + 1, step):
            try:
                start = time.perf_counter()
                self.cipher.generate_keys(n=n, min_bits=bits)
                elapsed = time.perf_counter() - start
                ns.append(n)
                times.append(elapsed)
                row = self.time_table.rowCount()
                self.time_table.insertRow(row)
                self.time_table.setItem(row, 0, QTableWidgetItem(str(n)))
                self.time_table.setItem(row, 1, QTableWidgetItem(f"{elapsed:.6f}"))
                self.plot_status_label.setText(f"Замер для n={n}: {elapsed:.3f} сек.")
                QApplication.processEvents()
            except Exception as e:
                self.plot_status_label.setText(f"Ошибка при генерации для n={n}: {e}")
                break

        if ns and times:
            self.plot_canvas.plot(ns, times)
            self.plot_status_label.setText("График построен.")
        else:
            self.plot_status_label.setText("Данные для графика отсутствуют.")


def run_app():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    light_palette = QPalette()
    light_palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
    light_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.black)
    light_palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.white)
    light_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(225, 225, 225))
    light_palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
    light_palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.black)
    light_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.black)
    light_palette.setColor(QPalette.ColorRole.Button, QColor(230, 230, 230))
    light_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
    light_palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    light_palette.setColor(QPalette.ColorRole.Highlight, QColor(100, 100, 255))
    light_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)

    app.setPalette(light_palette)
    window = KnapsackGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_app()