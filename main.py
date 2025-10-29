import http.server
import socketserver
import socket
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, Toplevel
import tkinter.ttk as ttk
import threading
import shutil
import sys
import urllib.parse
import requests
import json
import sqlite3
import hashlib
import time

# --- [ CONFIGURACIÓN GLOBAL ] ---
MULTIDESK_DIR = os.path.join(os.getcwd(), 'MultiDesk')
UPLOAD_LOG_FILE = os.path.join(MULTIDESK_DIR, '.upload_log.json')
DB_NAME = os.path.join(os.getcwd(), 'multidesk.db')
FILE_UPDATE_INTERVAL = 5000 # 5 segundos
HOST_SYSTEM_NAME = socket.gethostname() 

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
        local_path = urllib.parse.unquote(self.path.lstrip('/'))
        file_path = os.path.join(self.base_dir, local_path)

        if self.path == '/status':
            status = 'closed' if hasattr(self.server, 'closed') and self.server.closed else 'open'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"status":"{status}"}}'.encode('utf-8'))
            
        elif self.path == '/files_list':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # Registrar usuario al acceder a la lista (sin subir archivos)
            uploader = self.headers.get('X-Username')
            client_ip = self.get_client_ip()
            if uploader and self.app and self.app.is_host:
                self.server.user_map[client_ip] = uploader
            
            files_data = {
                'host_username': self.app.current_user if self.app and self.app.is_host else '',
                'files': []
            }
            
            EXCLUDED_FILES = {os.path.basename(UPLOAD_LOG_FILE), os.path.basename(DB_NAME)}
            
            for fname in os.listdir(self.base_dir):
                if os.path.isfile(os.path.join(self.base_dir, fname)) and not fname.startswith('.') and fname not in EXCLUDED_FILES:
                    uploader = self.app.upload_history.get(fname, '') if self.app else ''
                    files_data['files'].append({'name': urllib.parse.quote(fname), 'uploader': uploader}) 
            
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
            fname_encoded = self.headers.get('X-Filename')
            client_ip = self.get_client_ip()

            if fname_encoded:
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


# --- [ PANEL DE DEBUG ] ---
class DebugPanel:
    def __init__(self, master, app):
        self.app = app
        self.dialog = Toplevel(master)
        self.dialog.title("Panel de Diagnóstico")
        self.dialog.geometry("500x150")
        self.dialog.transient(master)
        
        tk.Label(self.dialog, text="Estado de la Conexión:", font=('Arial', 12, 'bold')).pack(pady=5)
        self.debug_text = tk.StringVar(self.dialog, value="")
        self.debug_label = tk.Label(self.dialog, textvariable=self.debug_text, font=('Arial', 10), justify=tk.LEFT)
        self.debug_label.pack(pady=10, padx=10)

    def update_info(self, message, is_error=False):
        color = 'red' if is_error else 'blue'
        prefix = "[ERROR] " if is_error else "[DEBUG] "
        
        # Usamos after(0, ...) para asegurarnos de que la actualización de la GUI se haga en el hilo principal
        self.dialog.after(0, lambda: self.debug_label.config(fg=color))
        self.dialog.after(0, lambda: self.debug_text.set(prefix + message))


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
        tk.Label(self.tab_users, text="Usuarios activos:", font=('Arial', 10)).pack(pady=5)
        
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
        # El host debe confirmar que desea cerrar la sala
        if messagebox.askyesno("Cerrar Sala", "¿Estás seguro de que quieres cerrar la sala y desconectar a todos los usuarios?"):
            if self.app.server:
                # El shutdown debe ejecutarse en un hilo separado ya que bloquea el hilo principal
                threading.Thread(target=self.app.server.shutdown, daemon=True).start()
                self.app.server = None # Limpiar la referencia
            
            self.dialog.destroy()
            self.app.is_host = False
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
        self.files_listbox = None
        self.last_files = set()
        self.selected_file_name = None
        self.upload_history = {}
        self.session = requests.Session()
        self.current_user = None
        self.host_username = None
        self.room_title_var = None
        self.client_updater_running = False
        self.ip_display_label = None
        self.debug_panel_instance = None
        self.port = 8000  # Puerto predeterminado
        self.server_error = None # 🆕 Para comunicar errores de servidor del hilo (ej. puerto ocupado)

        self.setup_db()
        self.setup_main_menu()
        self.load_upload_history()
        
    # Función centralizada para actualizar el panel de debug
    def update_debug_info(self, message, is_error=False):
        if self.debug_panel_instance:
            self.debug_panel_instance.update_info(message, is_error)
        else:
            # Si el panel no está abierto, imprime en consola
            print(f"{'[ERROR]' if is_error else '[DEBUG]'} {message}")

    # --- [ Funciones de Red ] ---
    def _get_local_ip(self):
        try:
            # Método más robusto para obtener la IP LAN
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            # Intenta conectarse a una IP no enrutada (no envía datos), solo para obtener la IP de la interfaz
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
            s.close()
            return IP
        except Exception:
            return "127.0.0.1"
            
    # Función para mostrar la IP local
    def get_my_ip_for_sharing(self):
        """Muestra la dirección IP local del equipo bajo el botón."""
        if self.ip_display_label:
            self.ip_display_label.config(text=f"Tu dirección IP local es: {self.local_ip}", fg='darkgreen')

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
            self.current_user = username
            return True, "Registro exitoso."
        except sqlite3.IntegrityError:
            return False, "El usuario ya existe. El nombre de usuario debe ser único."
        except Exception as e:
            return False, f"Error: {e}"

    def authenticate_user(self, username, password):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute("SELECT password_hash FROM Usuarios WHERE username=?", (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if not user_data:
            return False, "Usuario no encontrado"

        h_password_db = user_data[0]
        h_password_input = self._hash_password(password)

        if h_password_db == h_password_input:
            self.current_user = username
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
        self.client_updater_running = False
        self.host_username = None
        self.room_title_var = None
        
        # Destruye el panel de debug si existe al volver al menú principal
        if self.debug_panel_instance and self.debug_panel_instance.dialog.winfo_exists():
             self.debug_panel_instance.dialog.destroy()
        self.debug_panel_instance = None
        
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text='MultiDesk', font=('Arial', 18)).pack(pady=10)
        tk.Button(self.root, text='Hostear sala', width=20, command=self.host_room).pack(pady=5)
        tk.Button(self.root, text='Conectarse a sala', width=20, command=self.connect_room).pack(pady=5)
        
        # Botón de accesibilidad y Label de visualización
        tk.Button(self.root, text='Mostrar mi dirección IP', width=40, command=self.get_my_ip_for_sharing, bg='yellow').pack(pady=10)
        self.ip_display_label = tk.Label(self.root, text='', font=('Arial', 10, 'bold'))
        self.ip_display_label.pack(pady=2)
        
        tk.Button(self.root, text='Registrar usuario', width=20, command=self.show_register_dialog).pack(pady=5)
        
    def show_port_dialog(self, initial_port):
        """Muestra un diálogo para que el usuario configure el puerto de conexión."""
        new_port = simpledialog.askinteger('Configurar Puerto', 
                                          f'Ingresa un nuevo puerto (Actual: {initial_port}).',
                                          initialvalue=initial_port,
                                          minvalue=1024, maxvalue=65535)
        return new_port

    def open_debug_panel(self):
        # Se asegura de crear el panel solo si no existe
        if not self.debug_panel_instance or not self.debug_panel_instance.dialog.winfo_exists():
            self.debug_panel_instance = DebugPanel(self.root, self)
        self.debug_panel_instance.dialog.lift()

    def _ask_credentials_and_authenticate(self):
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
            if msg == "Usuario no encontrado":
                confirm = messagebox.askyesno('Error de Login', 
                                              f"El usuario '{username}' no existe.\n¿Quieres registrarte ahora?")
                if confirm:
                    self.show_register_dialog(username=username, password=password)
                    return self.current_user is not None 
                return False
            else:
                messagebox.showerror('Error', msg)
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
        self.host_username = self.current_user
        
        # 1. Creamos un Event para que el thread pueda avisar que terminó de intentar iniciar
        self.server_started_event = threading.Event() 
        self.server_error = None # Limpiamos el error anterior
        self._start_server_thread()
        
        # 2. Esperamos a que el thread termine de intentar iniciar (máx. 5 seg)
        self.server_started_event.wait(timeout=5)
        
        # 3. Verificamos el resultado en el hilo principal
        if self.server_error:
            # Si hubo un error capturado en el hilo, lo manejamos
            self._handle_server_startup_error() 
        elif self.server:
            # Si el servidor se inicializó correctamente
            self._on_server_started_successfully()
        else:
            # Si el evento no se activó (timeout) o el servidor es None (fallo desconocido)
            messagebox.showerror("Error de Host", "El intento de hostear la sala falló sin un error específico. Inténtalo de nuevo.")
            self.is_host = False
            self.setup_main_menu()

    def _start_server_thread(self):
        """Inicia el servidor en un hilo separado."""
        def run_server():
            try:
                handler = lambda *args, **kwargs: CustomHandler(*args, app_instance=self, base_dir=MULTIDESK_DIR, **kwargs)
                
                # Intenta iniciar el servidor 
                self.server = AuthTCPServer(("0.0.0.0", self.port), handler, set())
                self.server.app_instance = self
                
                # Éxito: Indica al hilo principal que proceda
                self.server_started_event.set()
                
                self.server.serve_forever()
                
            except (OSError, socket.error) as e:
                # Fallo: Almacena el error y notifica al hilo principal
                self.server_error = str(e)
                self.server = None # Aseguramos que la referencia del server es nula
                self.server_started_event.set() # Notifica al hilo principal que la espera ha terminado
                print(f"[SERVER THREAD FAIL] Error capturado: {self.server_error}") # Debug interno
            
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

    def _on_server_started_successfully(self):
        """Se ejecuta después de que el servidor se inicia sin errores."""
        messagebox.showinfo(
            "Dirección IP del Host", 
            f"Tu dirección IP que deben usar los clientes es:\n\n{self.local_ip}\n\n"
            f"¡Asegúrate de que el puerto {self.port} esté abierto en tu firewall!"
        )
        self.show_room_window()
        self.server.user_map[self.local_ip] = self.current_user
        self.open_debug_panel() 
        self.update_debug_info(f'Hosteando: {self.local_ip} en puerto {self.port}')
        
    def _handle_server_startup_error(self):
        """Maneja el error devuelto por el hilo del servidor en el hilo principal."""
        error_msg = self.server_error
        self.is_host = False # Resetea el estado host si el inicio falló.
        self.server_error = None # Limpia el error

        # Detección de error de "Address already in use" o "Puerto en uso"
        if 'address already in use' in error_msg.lower() or 'en uso' in error_msg.lower() or any(err in error_msg for err in ['10048', '98', '48']):
            self._handle_port_in_use_error_dialog() # Muestra el diálogo de reintento
        else:
            # Error inesperado
            messagebox.showerror("Error de Host", f"Error inesperado al iniciar el servidor: {error_msg}")
            self.setup_main_menu()

    def _handle_port_in_use_error_dialog(self):
        """Muestra el diálogo para cambiar de puerto y reintentar."""
        if not messagebox.askyesno(
            "Error al Hostear Sala (Puerto en uso)",
            f"El puerto {self.port} no está disponible, probablemente lo está usando otra aplicación.\n"
            "¿Quieres ingresar un **puerto diferente** para intentar hostear la sala de nuevo?"
        ):
            self.setup_main_menu()
            return
        
        # Si el usuario quiere cambiar el puerto
        new_port = self.show_port_dialog(self.port + 1)
        
        if new_port:
            self.port = new_port
            messagebox.showinfo("Reintento", f"Intentando hostear la sala con el nuevo puerto: {self.port}...")
            # Intenta hostear de nuevo con el nuevo puerto (recursivo)
            self.host_room() 
        else:
            self.setup_main_menu()

    def connect_room(self):
        if not self._ask_credentials_and_authenticate():
            return
        
        # Pide la IP y el Puerto al Cliente
        host_info = simpledialog.askstring('Conectar', 
                                          f'Dirección y Puerto del Host (ej. 192.168.1.10:{self.port}):',
                                          initialvalue=f'{self.local_ip}:{self.port}')
        if not host_info:
            return
        
        try:
            if ':' in host_info:
                ip_parts = host_info.split(':')
                self.host_ip = ip_parts[0].strip()
                self.port = int(ip_parts[1].strip())
            else:
                self.host_ip = host_info.strip()
            
            if not self.host_ip:
                 messagebox.showerror('Error', 'Debe ingresar una dirección IP válida.')
                 return
                 
        except (ValueError, IndexError):
            messagebox.showerror('Error', 'Formato de IP y Puerto incorrecto. Use: IP:PUERTO o solo IP.')
            return


        self.is_host = False

        if self.connect_to_server(self.host_ip):
            self.show_room_window()
            self.open_debug_panel()
            self.update_debug_info(f'Conectado a {self.host_ip} en puerto {self.port}')
            
            self.client_updater_running = True
            threading.Thread(target=self.fetch_and_update_client_files, daemon=True).start()
        else:
            messagebox.showerror('Error de Conexión', 
                                 f'No se pudo establecer la conexión HTTP con {self.host_ip} usando el puerto {self.port}.\nVerifica que el Host haya iniciado la sala y que el puerto {self.port} no esté bloqueado por un cortafuegos en ambos equipos.')
             
    def connect_to_server(self, ip):
        """Intenta realizar una petición GET para verificar si el servidor está activo."""
        try:
            r = self.session.get(f'http://{ip}:{self.port}/', timeout=3)
            r.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            # Captura el error para el debug panel (aunque no esté visible, registra el intento)
            self.update_debug_info(f'Error al conectar: {e}', is_error=True)
            return False

    def show_room_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10, padx=10, fill='x')
        
        self.room_title_var = tk.StringVar(self.root)
        
        if self.is_host:
            self.room_title_var.set(f'Sala: {self.current_user} (HOST) | Puerto: {self.port}')
        else:
            self.room_title_var.set(f'Sala: (Cliente) - {self.current_user} | Puerto: {self.port}')

        tk.Label(top_frame, textvariable=self.room_title_var, font=('Arial', 16)).pack(side=tk.LEFT)
        
        if self.is_host:
            tk.Button(top_frame, text='Panel de Control', command=self.open_control_panel, bg='lightblue').pack(side=tk.RIGHT)
        
        # Botón para abrir el panel de Debug (SOLO en la Sala)
        tk.Button(self.root, text='Diagnóstico', command=self.open_debug_panel, bg='lightgray').pack(pady=5)
        
        tk.Button(self.root, text='Seleccionar Archivo', command=self.select_file).pack(pady=5)
        tk.Button(self.root, text='Salir', command=self.leave_room).pack(pady=5)
        
        # Etiqueta de la lista de archivos
        tk.Label(self.root, text='Lista de Archivos Compartidos:', font=('Arial', 10, 'bold')).pack(pady=(10, 0))

        self.files_listbox = tk.Listbox(self.root, width=70)
        self.files_listbox.pack()
        self.files_listbox.bind('<Double-Button-1>', self.open_selected_file)
        self.update_files()
        
    def open_control_panel(self):
        HostControlPanel(self.root, self)

    def leave_room(self):
        self.client_updater_running = False
        
        if self.is_host:
            # Limpieza para el HOST: Apagar el servidor completamente
            if self.server:
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                self.server = None
            self.is_host = False
            self.update_debug_info("Servidor detenido.", is_error=False)
            messagebox.showinfo("Sala Cerrada", "El servidor se ha detenido. Volviendo al menú principal.")
        
        # Limpieza para el CLIENTE: simplemente vuelve al menú principal y resetea el puerto a 8000
        self.port = 8000
        self.setup_main_menu()

    def fetch_and_update_client_files(self):
        while self.client_updater_running:
            try:
                url = f'http://{self.host_ip}:{self.port}/files_list'
                # Envía el Username en el encabezado para registrarse en el Host
                headers = {'X-Username': self.current_user, 'X-Client-Ip': self.local_ip} 
                r = self.session.get(url, headers=headers, timeout=3)
                r.raise_for_status()

                files_response = r.json()
                
                self.host_username = files_response['host_username']
                
                # Actualiza el título del Label en la ventana principal
                self.root.after(0, lambda: self.room_title_var.set(f'Sala: {self.host_username} (HOST) - {self.current_user} (Cliente) | Puerto: {self.port}'))
                
                files_data = files_response['files']
                
                if self.files_listbox:
                    self.files_listbox.delete(0, tk.END)
                    for item in files_data:
                        fname = urllib.parse.unquote(item['name'])
                        uploader = item['uploader']
                        display = f"{fname:<40} (Subido por: {uploader})" if uploader else fname
                        self.files_listbox.insert(tk.END, display)
                    
                    self.update_debug_info("Lista de archivos actualizada.", is_error=False)
                        
            except requests.exceptions.RequestException as e:
                if self.client_updater_running:
                    # Muestra error de actualización en el panel
                    self.update_debug_info(f"Fallo al obtener lista de archivos: {e}", is_error=True)
            
            time.sleep(FILE_UPDATE_INTERVAL / 1000)

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
                url = f'http://{self.host_ip}:{self.port}/'
                headers = {'X-Filename': urllib.parse.quote(file_name), 
                           'X-Client-Ip': self.local_ip, 
                           'X-Username': self.current_user}
                r = self.session.post(url, data=data, headers=headers)
                if r.status_code == 200:
                    shutil.copy(file_path, dest_path) 
                    messagebox.showinfo("Archivo enviado", f"Se subió {file_name}.")
                else:
                    self.update_debug_info(f"Fallo al subir archivo. Código HTTP: {r.status_code}", is_error=True)
            except Exception as e:
                self.update_debug_info(f'Error de envío: {e}', is_error=True)

    def update_files(self):
        if self.files_listbox:
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