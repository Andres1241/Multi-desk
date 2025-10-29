import http.server
import socketserver
import socket
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, Toplevel
import tkinter.ttk as ttk # Necesario para el notebook en HostControlPanel
import threading
import shutil
import sys
import urllib.parse
import requests
from bs4 import BeautifulSoup
import json
import sqlite3
import hashlib
import time # Para el retardo en la actualización de archivos del cliente

# --- [ CONFIGURACIÓN GLOBAL ] ---
PORT = 8000
MULTIDESK_DIR = os.path.join(os.getcwd(), 'MultiDesk')
UPLOAD_LOG_FILE = os.path.join(MULTIDESK_DIR, '.upload_log.json')
# La DB se guarda en el directorio raíz, fuera de MultiDesk
DB_NAME = os.path.join(os.getcwd(), 'multidesk.db')
FILE_UPDATE_INTERVAL = 5000 # 5 segundos para actualización de archivos del cliente

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
        self.participants_ips = set()
        self.user_map = {}
        self.closed = False
        self.app_instance = None
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def verify_request(self, request, client_address):
        ip = client_address[0]
        self.participants_ips.add(ip)
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
        # 🔧 Decodificación de URL para manejar espacios
        local_path = urllib.parse.unquote(self.path.lstrip('/'))
        file_path = os.path.join(self.base_dir, local_path)

        if self.path == '/status':
            status = 'closed' if hasattr(self.server, 'closed') and self.server.closed else 'open'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"status":"{status}"}}'.encode('utf-8'))
           
        elif self.path == '/files_list': # 🆕 Endpoint para que el cliente obtenga la lista
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
           
            files_data = []
            EXCLUDED_FILES = {os.path.basename(UPLOAD_LOG_FILE), os.path.basename(DB_NAME)}
           
            for fname in os.listdir(self.base_dir):
                if os.path.isfile(os.path.join(self.base_dir, fname)) and not fname.startswith('.') and fname not in EXCLUDED_FILES:
                    uploader = self.app.upload_history.get(fname, '') if self.app else ''
                    # 🆕 Se envía el nombre de archivo codificado y el subidor
                    files_data.append({'name': urllib.parse.quote(fname), 'uploader': uploader})
           
            self.wfile.write(json.dumps(files_data).encode('utf-8'))

        elif self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            files = os.listdir(self.base_dir)
            html = "<html><body><h2>Archivos disponibles</h2><ul>"
           
            EXCLUDED_FILES = {os.path.basename(UPLOAD_LOG_FILE), os.path.basename(DB_NAME)}

            for fname in files:
                if os.path.isfile(os.path.join(self.base_dir, fname)) and not fname.startswith('.'):
                    if fname in EXCLUDED_FILES:
                        continue
                    # 🔧 Codificación de URL para el link
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
            # El cliente ya envía el nombre de archivo codificado para prevenir problemas.
            fname_encoded = self.headers.get('X-Filename')
            client_ip = self.get_client_ip()

            if fname_encoded:
                # 🔧 Decodificación del nombre de archivo (que podría tener espacios)
                fname = urllib.parse.unquote(fname_encoded)
                uploader = self.headers.get('X-Username')
               
                if uploader and self.server.app_instance and self.server.app_instance.is_host:
                    self.server.user_map[client_ip] = uploader
                   
                file_path = os.path.join(self.base_dir, fname)
                with open(file_path, 'wb') as f:
                    f.write(field_data)

                if self.app and self.app.is_host:
                    self.app.register_upload(fname, uploader if uploader else client_ip)
                   
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')
            else:
                self.send_error(400, "No filename provided")
        except Exception as e:
            print(f"[ERROR POST] {e}")
            self.send_error(500, f"Error interno: {e}")


# --- [ PANEL DE CONTROL DEL HOST ] ---
class HostControlPanel:
    def __init__(self, master, app):
        self.master = master
        self.app = app
        self.dialog = Toplevel(master)
        self.dialog.title("Panel de Control del Host")
        self.dialog.geometry("800x450")
        self.dialog.transient(master)
        self.dialog.grab_set()

        self.notebook = ttk.Notebook(self.dialog)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        self.tab_users = tk.Frame(self.notebook)
        self.notebook.add(self.tab_users, text='Usuarios Conectados')
        self._setup_users_tab()

        self.tab_files = tk.Frame(self.notebook)
        self.notebook.add(self.tab_files, text='Gestión de Archivos')
        self._setup_files_tab()

        tk.Button(self.dialog, text="Cerrar Sala", fg="red", command=self.close_room).pack(pady=10)

        self.update_users_list()


    def _setup_users_tab(self):
        tk.Label(self.tab_users, text="Usuarios activos (se registran al subir un archivo):", font=('Arial', 10)).pack(pady=5)
       
        self.users_listbox = tk.Listbox(self.tab_users, width=50, height=15)
        self.users_listbox.pack(pady=10, padx=10)

    def _setup_files_tab(self):
        tk.Label(self.tab_files, text="Archivos en MultiDesk (Selección múltiple con Ctrl/Shift):", font=('Arial', 10)).pack(pady=5)
       
        self.file_listbox_control = tk.Listbox(self.tab_files, selectmode=tk.MULTIPLE, width=70, height=15)
        self.file_listbox_control.pack(pady=5, padx=10)
        self.update_file_list_control()

        btn_frame = tk.Frame(self.tab_files)
        btn_frame.pack(pady=10)
       
        tk.Button(btn_frame, text="Eliminar Seleccionados", fg="orange", command=self.delete_selected_files).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Eliminar TODOS los Archivos", fg="red", command=self.delete_all_files).pack(side=tk.LEFT, padx=5)


    def update_users_list(self):
        if not self.app.server or not hasattr(self.app.server, 'user_map'):
            return

        self.users_listbox.delete(0, tk.END)
        users = set(self.app.server.user_map.values())
       
        if self.app.current_user:
            self.users_listbox.insert(tk.END, f"{self.app.current_user} (HOST)")
            users.discard(self.app.current_user)

        for user in sorted(list(users)):
            self.users_listbox.insert(tk.END, user)

        self.dialog.after(5000, self.update_users_list)
       

    def update_file_list_control(self):
        self.file_listbox_control.delete(0, tk.END)
        EXCLUDED_FILES = {os.path.basename(UPLOAD_LOG_FILE), os.path.basename(DB_NAME)}

        for fname in sorted(os.listdir(MULTIDESK_DIR)):
            if not fname.startswith('.') and fname not in EXCLUDED_FILES:
                self.file_listbox_control.insert(tk.END, fname)
       
        self.app.update_files()

    def delete_selected_files(self):
        selected_indices = self.file_listbox_control.curselection()
        if not selected_indices:
            messagebox.showinfo("Información", "No hay archivos seleccionados.")
            return

        confirm = messagebox.askyesno("Confirmar Eliminación", f"¿Estás seguro de que quieres eliminar {len(selected_indices)} archivo(s) seleccionado(s)?")
        if confirm:
            for index in selected_indices:
                filename = self.file_listbox_control.get(index)
                filepath = os.path.join(MULTIDESK_DIR, filename)
                try:
                    os.remove(filepath)
                    if filename in self.app.upload_history:
                        del self.app.upload_history[filename]
                except Exception as e:
                    messagebox.showerror("Error", f"No se pudo eliminar {filename}: {e}")

            self.app.save_upload_history()
            self.update_file_list_control()
            self.app.update_files()
            messagebox.showinfo("Éxito", "Archivos eliminados correctamente.")

    def delete_all_files(self):
        confirm = messagebox.askyesno("CONFIRMAR ELIMINACIÓN TOTAL",
                                     "ESTA ACCIÓN ELIMINARÁ TODOS LOS ARCHIVOS COMPARTIDOS.\n¿Estás seguro?")
        if confirm:
            EXCLUDED_FILES = {os.path.basename(UPLOAD_LOG_FILE), os.path.basename(DB_NAME)}
            files_deleted = 0
            for fname in os.listdir(MULTIDESK_DIR):
                filepath = os.path.join(MULTIDESK_DIR, fname)
                if os.path.isfile(filepath) and not fname.startswith('.') and fname not in EXCLUDED_FILES:
                    try:
                        os.remove(filepath)
                        files_deleted += 1
                    except Exception as e:
                        print(f"Error al borrar {fname}: {e}")
           
            self.app.upload_history = {}
            self.app.save_upload_history()
            self.update_file_list_control()
            self.app.update_files()
            messagebox.showinfo("Éxito", f"Se eliminaron {files_deleted} archivos de la sala.")

    def close_room(self):
        if self.app.server:
            threading.Thread(target=self.app.server.shutdown).start()
        messagebox.showinfo("Sala Cerrada", "El servidor se ha detenido. Volviendo al menú principal.")
        self.dialog.destroy()
        self.app.setup_main_menu()

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
        self.current_user = None
        self.client_updater_running = False # Bandera para el hilo de actualización del cliente

        self.setup_db()
        self.setup_main_menu()
        self.load_upload_history()
       
    # --- [ Funciones de Red ] ---
    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
           
    # 🆕 Función para resolver nombre de host
    def _resolve_host_ip(self, host_name):
        try:
            # Intenta obtener la IP a partir del nombre de host
            return socket.gethostbyname(host_name)
        except socket.gaierror:
            # Si falla, asume que ya es una IP y la devuelve
            return host_name

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
            self.current_user = username # 🆕 Recordar el usuario registrado
            return True, "Registro exitoso."
        except sqlite3.IntegrityError:
            return False, "El usuario ya existe."
        except Exception as e:
            return False, f"Error: {e}"

    def check_user_exists(self, username):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Usuarios WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()
        return user is not None

    def authenticate_user(self, username, password):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
       
        # 🆕 Verificar si el usuario existe primero
        cursor.execute("SELECT password_hash FROM Usuarios WHERE username=?", (username,))
        user_data = cursor.fetchone()
        conn.close()
       
        if not user_data:
            return False, "Usuario no encontrado"

        h_password_db = user_data[0]
        h_password_input = self._hash_password(password)

        if h_password_db == h_password_input:
            self.current_user = username # 🆕 Recordar el usuario autenticado
            return True, "Autenticación exitosa"
        else:
            return False, "Contraseña incorrecta"

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
        # Detener el hilo de actualización si estaba corriendo
        self.client_updater_running = False
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text='MultiDesk', font=('Arial', 18)).pack(pady=10)
        tk.Button(self.root, text='Hostear sala', width=20, command=self.host_room).pack(pady=5)
        tk.Button(self.root, text='Conectarse a sala', width=20, command=self.connect_room).pack(pady=5)
        tk.Button(self.root, text='Registrar usuario', width=20, command=self.show_register_dialog).pack(pady=5)
        self.debug_label = tk.Label(self.root, text='', fg='blue')
        self.debug_label.pack(pady=2)

    def _ask_credentials_and_authenticate(self):
        # 🆕 Si ya hay un usuario logueado (por registro o login previo), saltar
        if self.current_user:
            messagebox.showinfo('Info', f'Ya estás logueado como {self.current_user}.')
            return True
           
        username = simpledialog.askstring('Autenticación', 'Usuario:')
        if not username:
            return False
        password = simpledialog.askstring('Autenticación', 'Contraseña:', show='*')
        if not password:
            return False
       
        success, msg = self.authenticate_user(username, password)

        if success:
            messagebox.showinfo('Éxito', f'Bienvenido, {self.current_user}.')
            return True
        else:
            # 🆕 Si el usuario no existe, preguntar si quiere registrarse
            if msg == "Usuario no encontrado":
                confirm = messagebox.askyesno('Error de Login',
                                              f"El usuario '{username}' no existe.\n¿Quieres registrarte ahora?")
                if confirm:
                    self.show_register_dialog(username=username, password=password)
                    # Si el registro fue exitoso, current_user se habrá establecido
                    return self.current_user is not None
                return False
            else:
                messagebox.showerror('Error', 'Contraseña incorrecta.')
                return False

    def show_register_dialog(self, username=None, password=None):
        dialog = Toplevel(self.root)
        dialog.title("Registrar Usuario")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Usuario:").pack(pady=5)
        user_entry = tk.Entry(dialog)
        user_entry.pack()
        if username: user_entry.insert(0, username)
       
        tk.Label(dialog, text="Contraseña:").pack(pady=5)
        pass_entry = tk.Entry(dialog, show='*')
        pass_entry.pack()
        if password: pass_entry.insert(0, password)

        def register_action():
            user = user_entry.get()
            passwd = pass_entry.get()
            success, msg = self.register_user(user, passwd)
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
       
        if self.server:
            self.server.user_map[self.local_ip] = self.current_user
           
        self.debug_label.config(text=f'[DEBUG] Hosteando en {self.local_ip}:{PORT} ({self.current_user})')

    def connect_room(self):
        if not self._ask_credentials_and_authenticate():
            return
       
        # 🔧 Pide el nombre de host en lugar de la IP
        host_name = simpledialog.askstring('Conectar', 'Nombre de Host o IP del host:')
        if host_name:
            ip = self._resolve_host_ip(host_name) # 🔧 Resuelve el nombre a IP
            if ip:
                self.host_ip = ip
                self.is_host = False
                self.connect_to_server(ip)
                self.show_room_window()
                self.debug_label.config(text=f'[DEBUG] Conectado a {host_name} ({ip}:{PORT})')
               
                # 🆕 Inicia el hilo de actualización de archivos para el cliente
                self.client_updater_running = True
                threading.Thread(target=self.fetch_and_update_client_files, daemon=True).start()
            else:
                 messagebox.showerror('Error de Conexión', 'No se pudo resolver el nombre de host o IP.')

    def show_room_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
       
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10, padx=10, fill='x')
       
        tk.Label(top_frame, text=f'Sala de {self.current_user}', font=('Arial', 16)).pack(side=tk.LEFT)
       
        if self.is_host:
            tk.Button(top_frame, text='Panel de Control', command=self.open_control_panel, bg='lightblue').pack(side=tk.RIGHT)

        tk.Button(self.root, text='Seleccionar Archivo', command=self.select_file).pack(pady=5)
        tk.Button(self.root, text='Salir', command=self.leave_room).pack(pady=5)
       
        self.debug_label = tk.Label(self.root, text='', fg='blue')
        self.debug_label.pack(pady=2)
       
        self.files_listbox = tk.Listbox(self.root, width=70)
        self.files_listbox.pack()
        self.files_listbox.bind('<Double-Button-1>', self.open_selected_file)
        self.update_files()
       
    def open_control_panel(self):
        HostControlPanel(self.root, self)

    def leave_room(self):
        self.client_updater_running = False # Detener el hilo de actualización
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
                pass
        except Exception as e:
            self.debug_label.config(text=f'[DEBUG] Error de conexión: {e}')
           
    # 🆕 Nuevo: Hilo para la actualización de archivos del cliente
    def fetch_and_update_client_files(self):
        while self.client_updater_running:
            try:
                # Se pide la lista de archivos al endpoint especial
                url = f'http://{self.host_ip}:{PORT}/files_list'
                r = self.session.get(url, timeout=3)
                r.raise_for_status() # Lanza excepción para códigos de error

                files_data = r.json()
               
                # Actualiza la lista en la GUI principal
                if self.files_listbox:
                    self.files_listbox.delete(0, tk.END)
                    for item in files_data:
                        # 🔧 Decodificación del nombre de archivo para mostrarlo
                        fname = urllib.parse.unquote(item['name'])
                        uploader = item['uploader']
                        display = f"{fname:<40} (Subido por: {uploader})" if uploader else fname
                        self.files_listbox.insert(tk.END, display)
                       
            except requests.exceptions.RequestException as e:
                # Esto es normal si el host ha cerrado la sala
                if self.client_updater_running:
                     print(f"Error al obtener archivos del host: {e}")
           
            time.sleep(FILE_UPDATE_INTERVAL / 1000) # Esperar 5 segundos

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
                # 🔧 Codificación del nombre de archivo para el encabezado
                headers = {'X-Filename': urllib.parse.quote(file_name),
                           'X-Client-Ip': self.local_ip,
                           'X-Username': self.current_user}
                r = self.session.post(url, data=data, headers=headers)
                if r.status_code == 200:
                    shutil.copy(file_path, dest_path)
                    messagebox.showinfo("Archivo enviado", f"Se subió {file_name}.")
            except Exception as e:
                self.debug_label.config(text=f'[DEBUG] Error de envío: {e}')

    def update_files(self):
        if self.is_host and self.files_listbox:
            self.files_listbox.delete(0, tk.END)
           
            EXCLUDED_FILES = {os.path.basename(UPLOAD_LOG_FILE), os.path.basename(DB_NAME)}

            for fname in sorted(os.listdir(MULTIDESK_DIR)):
                if not fname.startswith('.') and fname not in EXCLUDED_FILES:
                    uploader = self.upload_history.get(fname, '')
                    display = f"{fname:<40} (Subido por: {uploader})" if uploader else fname
                    self.files_listbox.insert(tk.END, display)

    def on_file_received(self, filename):
        self.update_files()

    def open_selected_file(self, event):
        try:
            index = self.files_listbox.curselection()[0]
            text = self.files_listbox.get(index)
            # El nombre del archivo es la primera parte, antes del espacio
            filename = text.split(' ')[0]
           
            # 🔧 Se usa el nombre de archivo tal cual está en la lista (que fue decodificado)
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