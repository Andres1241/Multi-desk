import http.server
import socketserver
import socket
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, Toplevel
import threading
import shutil
import sys
import urllib.parse
import requests
from bs4 import BeautifulSoup
import json
import sqlite3   # 🆕 Base de datos SQLite
import hashlib   # 🆕 Para hashear contraseñas


# --- [ CONFIGURACIÓN GLOBAL ] ---
PORT = 8000
MULTIDESK_DIR = os.path.join(os.getcwd(), 'MultiDesk')
UPLOAD_LOG_FILE = os.path.join(MULTIDESK_DIR, '.upload_log.json')
DB_NAME = os.path.join(MULTIDESK_DIR, 'multidesk.db')  # 🆕 Archivo de base de datos


# --- [ FUNCIÓN AUXILIAR ] ---
def open_file(filepath):
    """Abre un archivo usando el programa predeterminado del sistema operativo."""
    if sys.platform.startswith('darwin'):
        os.system(f'open "{filepath}"')
    elif os.name == 'nt':
        os.startfile(filepath)
    elif os.name == 'posix':
        os.system(f'xdg-open "{filepath}"')


# --- [ SERVIDOR Y HANDLER HTTP ] ---
class AuthTCPServer(socketserver.TCPServer):
    allow_reuse_address = True
    def __init__(self, server_address, RequestHandlerClass, allowed_clients, bind_and_activate=True):
        self.allowed_clients = allowed_clients
        self.participants = set()
        self.closed = False
        self.app_instance = None
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def verify_request(self, request, client_address):
        ip = client_address[0]
        self.participants.add(ip)
        return True


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, app_instance=None, base_dir=None, **kwargs):
        self.base_dir = base_dir or MULTIDESK_DIR
        self.app = app_instance
        super().__init__(*args, **kwargs)

    def get_client_ip(self):
        ip_from_header = self.headers.get('X-Client-Ip')
        if ip_from_header:
            return ip_from_header
        return self.client_address[0]

    def do_GET(self):
        local_path = urllib.parse.unquote(self.path.lstrip('/'))
        file_path = os.path.join(self.base_dir, local_path)

        if self.path == '/status':
            status = 'closed' if hasattr(self.server, 'closed') and self.server.closed else 'open'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"status":"{status}"}}'.encode('utf-8'))

        elif self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            files = os.listdir(self.base_dir)
            html = "<html><body><h2>Archivos disponibles</h2><ul>"
            for fname in files:
                if os.path.isfile(os.path.join(self.base_dir, fname)) and not fname.startswith('.'):
                    if fname == os.path.basename(UPLOAD_LOG_FILE):
                        continue
                    html += f'<li><a href="{urllib.parse.quote(fname)}">{fname}</a></li>'
            html += "</ul></body></html>"
            self.wfile.write(html.encode('utf-8'))

        elif os.path.isfile(file_path):
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.send_header("Content-Length", str(os.path.getsize(file_path)))
            self.end_headers()
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            length = int(self.headers['Content-Length'])
            field_data = self.rfile.read(length)
            fname = self.headers.get('X-Filename')
            client_ip = self.get_client_ip()

            if fname:
                file_path = os.path.join(self.base_dir, fname)
                with open(file_path, 'wb') as f:
                    f.write(field_data)

                if self.app and self.app.is_host:
                    uploader = self.headers.get('X-Username', client_ip)
                    self.app.register_upload(fname, uploader)

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')
            else:
                self.send_error(400, "No filename provided")
        except Exception as e:
            print(f"[ERROR POST] {e}")
            self.send_error(500, f"Error interno: {e}")


# --- [ APLICACIÓN TKINTER ] ---
class MultiDeskApp:
    def __init__(self, root):
        self.root = root
        self.root.title('MultiDesk')
        self.is_host = False
        self.server_thread = None
        self.server = None
        self.host_ip = ''
        self.local_ip = self._get_local_ip()
        self.debug_label = None
        self.files_listbox = None
        self.last_files = set()
        self.selected_file_name = None
        self.upload_history = {}
        self.session = requests.Session()
        self.current_user = None  # 🆕 Usuario autenticado

        self.setup_db()  # 🆕 Inicializa la DB
        self.setup_main_menu()
        self.load_upload_history()

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # --- [ Gestión de Base de Datos SQLite ] ---
    def setup_db(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Usuarios (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password):
        if not username or not password:
            return False, "El nombre de usuario y la contraseña no pueden estar vacíos."
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            h_password = self._hash_password(password)
            if len(password) < 4:
                return False, "La contraseña debe tener al menos 4 caracteres."
            cursor.execute("INSERT INTO Usuarios (username, password_hash) VALUES (?, ?)", (username, h_password))
            conn.commit()
            conn.close()
            return True, "Registro exitoso."
        except sqlite3.IntegrityError:
            return False, "El usuario ya existe."
        except Exception as e:
            return False, f"Error: {e}"

    def authenticate_user(self, username, password):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        h_password = self._hash_password(password)
        cursor.execute("SELECT * FROM Usuarios WHERE username=? AND password_hash=?", (username, h_password))
        user = cursor.fetchone()
        conn.close()
        if user:
            self.current_user = username
            return True
        return False

    # --- [ Manejo de Subidas ] ---
    def save_upload_history(self):
        if self.is_host:
            try:
                with open(UPLOAD_LOG_FILE, 'w') as f:
                    json.dump(self.upload_history, f, indent=4)
            except Exception as e:
                print(f"[ERROR LOG] {e}")

    def load_upload_history(self):
        if os.path.exists(UPLOAD_LOG_FILE):
            try:
                with open(UPLOAD_LOG_FILE, 'r') as f:
                    self.upload_history = json.load(f)
            except Exception:
                self.upload_history = {}

    def register_upload(self, filename, uploader):
        self.upload_history[filename] = uploader
        self.save_upload_history()
        self.on_file_received(filename)

    # --- [ GUI PRINCIPAL ] ---
    def setup_main_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text='MultiDesk', font=('Arial', 18)).pack(pady=10)
        tk.Button(self.root, text='Hostear sala', width=20, command=self.host_room).pack(pady=5)
        tk.Button(self.root, text='Conectarse a sala', width=20, command=self.connect_room).pack(pady=5)
        tk.Button(self.root, text='Registrar usuario', width=20, command=self.show_register_dialog).pack(pady=5)
        self.debug_label = tk.Label(self.root, text='', fg='blue')
        self.debug_label.pack(pady=2)

    def _ask_credentials_and_authenticate(self):
        username = simpledialog.askstring('Autenticación', 'Usuario:')
        if not username:
            return False
        password = simpledialog.askstring('Autenticación', 'Contraseña:', show='*')
        if not password:
            return False
        if self.authenticate_user(username, password):
            messagebox.showinfo('Éxito', f'Bienvenido, {self.current_user}.')
            return True
        else:
            messagebox.showerror('Error', 'Usuario o contraseña incorrectos.')
            return False

    def show_register_dialog(self):
        dialog = Toplevel(self.root)
        dialog.title("Registrar Usuario")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Usuario:").pack(pady=5)
        user_entry = tk.Entry(dialog)
        user_entry.pack()
        tk.Label(dialog, text="Contraseña:").pack(pady=5)
        pass_entry = tk.Entry(dialog, show='*')
        pass_entry.pack()

        def register_action():
            username = user_entry.get()
            password = pass_entry.get()
            success, msg = self.register_user(username, password)
            if success:
                messagebox.showinfo("Éxito", msg)
                dialog.destroy()
            else:
                messagebox.showerror("Error", msg)

        tk.Button(dialog, text="Registrar", command=register_action).pack(pady=10)
        self.root.wait_window(dialog)

    # --- [ HOST / CLIENTE ] ---
    def host_room(self):
        if not self._ask_credentials_and_authenticate():
            return
        if not os.path.exists(MULTIDESK_DIR):
            os.makedirs(MULTIDESK_DIR)
        self.is_host = True
        self.start_server()
        self.show_room_window()
        self.debug_label.config(text=f'[DEBUG] Hosteando en {self.local_ip}:{PORT} ({self.current_user})')

    def connect_room(self):
        if not self._ask_credentials_and_authenticate():
            return
        ip = simpledialog.askstring('Conectar', 'IP del host:')
        if ip:
            self.host_ip = ip
            self.is_host = False
            self.connect_to_server(ip)
            self.show_room_window()
            self.debug_label.config(text=f'[DEBUG] Conectado a {ip}:{PORT} ({self.current_user})')

    def show_room_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text=f'Sala de {self.current_user}', font=('Arial', 16)).pack(pady=10)
        tk.Button(self.root, text='Seleccionar Archivo', command=self.select_file).pack(pady=5)
        tk.Button(self.root, text='Salir', command=self.leave_room).pack(pady=5)
        self.debug_label = tk.Label(self.root, text='', fg='blue')
        self.debug_label.pack(pady=2)
        self.files_listbox = tk.Listbox(self.root, width=70)
        self.files_listbox.pack()
        self.files_listbox.bind('<Double-Button-1>', self.open_selected_file)
        self.update_files()

    def leave_room(self):
        if self.server:
            threading.Thread(target=self.server.shutdown).start()
        self.setup_main_menu()

    def start_server(self):
        def run_server():
            handler = lambda *args, **kwargs: CustomHandler(*args, app_instance=self, base_dir=MULTIDESK_DIR, **kwargs)
            self.server = AuthTCPServer(("0.0.0.0", PORT), handler, set())
            self.server.app_instance = self
            self.server.serve_forever()
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

    def connect_to_server(self, ip):
        try:
            r = self.session.get(f'http://{ip}:{PORT}/', timeout=3)
            if r.status_code in (200, 404):
                self.debug_label.config(text=f'[DEBUG] Conectado a {ip}')
        except Exception as e:
            self.debug_label.config(text=f'[DEBUG] Error: {e}')

    # --- [ Envío de Archivos ] ---
    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.send_file(file_path)

    def send_file(self, file_path):
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(MULTIDESK_DIR, file_name)

        if self.is_host:
            shutil.copy(file_path, dest_path)
            self.register_upload(file_name, self.current_user)
            messagebox.showinfo("Archivo enviado", f"Se agregó {file_name}.")
        else:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                url = f'http://{self.host_ip}:{PORT}/'
                headers = {'X-Filename': file_name, 'X-Client-Ip': self.local_ip, 'X-Username': self.current_user}
                r = self.session.post(url, data=data, headers=headers)
                if r.status_code == 200:
                    shutil.copy(file_path, dest_path)
                    messagebox.showinfo("Archivo enviado", f"Se subió {file_name}.")
            except Exception as e:
                self.debug_label.config(text=f'[DEBUG] Error: {e}')

    def update_files(self):
        if self.files_listbox:
            self.files_listbox.delete(0, tk.END)
            for fname in sorted(os.listdir(MULTIDESK_DIR)):
                if not fname.startswith('.') and fname != os.path.basename(UPLOAD_LOG_FILE):
                    uploader = self.upload_history.get(fname, '')
                    display = f"{fname:<40} (Subido por: {uploader})" if uploader else fname
                    self.files_listbox.insert(tk.END, display)

    def on_file_received(self, filename):
        self.update_files()

    def open_selected_file(self, event):
        try:
            index = self.files_listbox.curselection()[0]
            text = self.files_listbox.get(index)
            filename = text.split(' ')[0]
            open_file(os.path.join(MULTIDESK_DIR, filename))
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    if not os.path.exists(MULTIDESK_DIR):
        os.makedirs(MULTIDESK_DIR)
    root = tk.Tk()
    app = MultiDeskApp(root)
    root.protocol("WM_DELETE_WINDOW", app.leave_room)
    root.mainloop()
