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

# Función para limpieza (usada al cerrar en modo temporal)
def cleanup_multidesk(is_host=False):
    """Elimina todos los archivos del directorio MultiDesk, excluyendo logs y DB."""
    EXCLUDED_FILES = {os.path.basename(UPLOAD_LOG_FILE), os.path.basename(DB_NAME)}
    
    # El host puede tener un registro de uploads vacío, el cliente no
    if not is_host:
        EXCLUDED_FILES.add(os.path.basename(os.path.join(os.getcwd(), 'multidesk.db'))) # Protege la DB del cliente
        
    files_deleted = 0
    for fname in os.listdir(MULTIDESK_DIR):
        filepath = os.path.join(MULTIDESK_DIR, fname)
        if os.path.isfile(filepath) and not fname.startswith('.') and fname not in EXCLUDED_FILES:
            try:
                os.remove(filepath)
                files_deleted += 1
            except Exception as e:
                print(f"Error al borrar {fname} durante la limpieza: {e}")
    return files_deleted

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
        """Maneja las peticiones GET, incluyendo la descarga de archivos, lista de archivos y estado."""
        # Sanitizar el path recibido, eliminando el path inicial de la URL
        path = self.path
        if path.startswith('/'):
            path = path[1:]
            
        # -----------------------------------------------------
        # Manejo de peticiones /status (para verificar si el host está activo)
        if path == 'status':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'online', 'host': self.server.app.host_username}).encode('utf-8'))
            return
            
        # -----------------------------------------------------
        # Manejo de peticiones /files_list (para la lista de archivos)
        if path == 'files_list':
            
            # 1. Obtenemos el nombre desambiguado (ej: "Juan 1")
            # 🆕 Usamos la nueva función para obtener el nombre único.
            resolved_username = self._get_username_from_headers(self.headers)
            client_ip = self.headers.get('X-Client-Ip')
            
            if resolved_username and client_ip:
                
                # 2. Almacenamos el nombre desambiguado en el mapa del servidor.
                # Si es una nueva conexión, o si el nombre desambiguado es diferente:
                if client_ip not in self.server.user_map or self.server.user_map.get(client_ip) != resolved_username:
                    
                    # 💡 Almacenamos el nombre resuelto (que puede ser desambiguado o no)
                    self.server.user_map[client_ip] = resolved_username 
                    self.server.app.update_debug_info(f"Cliente '{resolved_username}' ({client_ip}) se ha conectado.")
                
                # 3. Devolver el nombre de usuario desambiguado en la respuesta HTTP
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                # 🆕 Devolvemos el nombre resuelto para que el cliente actualice su estado.
                self.send_header('X-Username-Resolved', urllib.parse.quote(resolved_username)) 
                self.end_headers()
                
                # Prepara la lista de archivos para enviar
                files_info = []
                for fname in os.listdir(MULTIDESK_DIR):
                    filepath = os.path.join(MULTIDESK_DIR, fname)
                    if os.path.isfile(filepath) and not fname.startswith('.'):
                        uploader = self.server.app.upload_history.get(fname, 'Desconocido')
                        files_info.append({
                            'name': fname,
                            'size': os.path.getsize(filepath),
                            'uploader': uploader
                        })

                self.wfile.write(json.dumps({'files': files_info, 'host_name': HOST_SYSTEM_NAME}).encode('utf-8'))
                return
            else:
                self.send_error(401, "Falta la autenticación (X-Username o X-Client-Ip).")
                return

        # -----------------------------------------------------
        # Manejo de peticiones de descarga de archivos
        
        # Decodificar el path para manejar espacios y caracteres especiales en nombres de archivos
        filename = urllib.parse.unquote(path)
        filepath = os.path.join(MULTIDESK_DIR, filename)
        
        # Evitar el acceso a archivos de log o DB
        if filename in {os.path.basename(UPLOAD_LOG_FILE), os.path.basename(DB_NAME)} or filename.startswith('.'):
             self.send_error(403, "Acceso denegado a archivos del sistema.")
             return
             
        # La lógica original de SimpleHTTPRequestHandler utiliza os.getcwd() como base.
        # Necesitamos sobrescribir para usar MULTIDESK_DIR y solo permitir descargas de archivos.
        if os.path.isfile(filepath):
            try:
                self.send_response(200)
                self.send_header("Content-type", self.guess_type(filepath))
                self.send_header("Content-Length", str(os.path.getsize(filepath)))
                # Sugerir la descarga con el nombre original del archivo
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.end_headers()

                with open(filepath, 'rb') as file:
                    shutil.copyfileobj(file, self.wfile)
            except Exception as e:
                self.send_error(500, f"Error al servir el archivo: {e}")
            return
        
        # Si no es un archivo de sistema, no es files_list, ni status, ni un archivo válido:
        self.send_error(404, "Archivo o Recurso no encontrado")

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
                    self.app.update_debug_info(f"Subida de {uploader}: {fname}") # 🆕 Debug Host
                    
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
    
    def _get_username_from_headers(self, headers):
        """
        Obtiene el nombre de usuario de los headers y, si es un nombre duplicado en la sesión
        actual (ya presente en user_map.values()), lo desambigua con un sufijo numérico 
        (ej: Juan 1, Juan 2).
        """
        username = headers.get('X-Username')
        if not username:
            return None
            
        server = self.server
        
        # 🆕 Lógica de Desambiguación: Solo aplicable si el nombre ya está en uso.
        
        # 1. Chequeo Rápido: Si el nombre ya está en uso por otro cliente, necesitamos desambiguar.
        if username in server.user_map.values():
            
            base_username = username
            counter = 1
            new_username = f"{base_username} {counter}"
            
            # Buscar el sufijo numérico más bajo que no esté en uso.
            while new_username in server.user_map.values():
                counter += 1
                new_username = f"{base_username} {counter}"
                
            return new_username
            
        # 2. Si el nombre no está en uso, se devuelve sin modificar.
        return username

    # 🆕 Maneja la eliminación de usuarios y archivos
    def do_DELETE(self):
        client_ip = self.get_client_ip()
        username = self.headers.get('X-Username')
        
        # 1. Solicitud de Salida de Cliente (/leave)
        if self.path == '/leave':
            if username and self.app and self.app.is_host:
                self.app.remove_client(client_ip, username)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
            return

        # 2. Solicitud de Eliminación de Archivo (/delete_file)
        elif self.path == '/delete_file':
            filename_encoded = self.headers.get('X-Filename')
            if not filename_encoded:
                self.send_error(400, "Filename header missing")
                return

            filename = urllib.parse.unquote(filename_encoded)
            success, msg = self.app.host_delete_file_check(filename, username) # 🆕 Lógica en App

            if success:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')
            else:
                self.send_error(403, msg) # 403 Prohibido o 400 Bad Request
            return

        self.send_error(404)

# --- [ PANEL DE DEBUG ] ---
class DebugPanel:
    def __init__(self, master, app):
        self.master = master
        self.app = app
        self.dialog = Toplevel(master)
        self.dialog.title("Panel de Diagnóstico (Debug)")
        self.dialog.geometry("600x350")
        self.dialog.transient(master)
        self.dialog.grab_set()
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_close)

        # Contenedor para la lista de mensajes
        frame = tk.Frame(self.dialog)
        frame.pack(pady=10, padx=10, expand=True, fill="both")

        # Configuración del Listbox y Scrollbar
        scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
        self.info_listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set, width=80, height=15)
        scrollbar.config(command=self.info_listbox.yview)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.info_listbox.pack(side=tk.LEFT, fill="both", expand=True)

        self.add_system_info()

    def add_system_info(self):
        """Añade información de sistema al inicio del panel."""
        self.update_info(f"--- [ INICIO DEL DIAGNÓSTICO ] ---")
        self.update_info(f"Sistema Operativo: {sys.platform} ({os.name})")
        self.update_info(f"Hostname: {HOST_SYSTEM_NAME}")
        self.update_info(f"IP Local (Reportada): {self.app.local_ip}")
        self.update_info(f"Directorio MultiDesk: {MULTIDESK_DIR}")
        self.update_info(f"---")

    def update_info(self, message, is_error=False):
        """Función para añadir mensajes al listbox desde cualquier parte de la app."""
        color = 'red' if is_error else 'darkgreen' if message.startswith('[DEBUG]') else 'black'
        
        # Insertar con la hora actual
        now = time.strftime("[%H:%M:%S]")
        display_message = f"{now} {message}"
        
        self.info_listbox.insert(tk.END, display_message)
        self.info_listbox.itemconfig(tk.END, {'fg': color})
        
        # Scroll automático al final
        self.info_listbox.see(tk.END)

    def on_close(self):
        """Limpia la referencia al cerrar el panel."""
        self.app.debug_panel_instance = None
        self.dialog.destroy()


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
                # 🆕 Indica que el servidor está cerrado antes del shutdown
                self.app.server.closed = True 
                
                # El shutdown debe ejecutarse en un hilo separado ya que bloquea el hilo principal
                threading.Thread(target=self.app.server.shutdown, daemon=True).start()
                self.app.server = None # Limpiar la referencia
                
            # 🆕 Limpieza si el HOST está en modo temporal
            if self.app.is_temporal_mode.get():
                cleanup_count = cleanup_multidesk(is_host=True)
                messagebox.showinfo("Limpieza", f"Modo temporal activo: Se eliminaron {cleanup_count} archivos locales.")

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
        self.server_error = None # Para comunicar errores de servidor del hilo (ej. puerto ocupado)
        self.is_temporal_mode = tk.BooleanVar(value=False)

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
    
    # 🆕 Función para eliminar clientes (usada por do_DELETE /leave)
    def remove_client(self, client_ip, username):
        if self.server:
            if client_ip in self.server.user_map and self.server.user_map[client_ip] == username:
                del self.server.user_map[client_ip]
                self.update_debug_info(f"Usuario {username} ({client_ip}) se desconectó.")
            if client_ip in self.server.participants_ips:
                 self.server.participants_ips.remove(client_ip)

    # 🆕 Función para que el Host verifique la eliminación solicitada por el Cliente
    def host_delete_file_check(self, filename, username):
        if not self.is_host:
            return False, "No autorizado: No es el host."
            
        uploader = self.upload_history.get(filename)
        
        if uploader != username:
            return False, f"No autorizado: Solo el uploader ({uploader}) puede eliminar este archivo."
            
        filepath = os.path.join(MULTIDESK_DIR, filename)
        if not os.path.exists(filepath):
            return False, "Archivo no encontrado."
            
        try:
            os.remove(filepath)
            if filename in self.upload_history:
                del self.upload_history[filename]
            self.save_upload_history()
            self.update_files()
            self.update_debug_info(f"Archivo eliminado por {username}: {filename}")
            return True, "Archivo eliminado correctamente."
        except Exception as e:
            return False, f"Error al eliminar {filename}: {e}"

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
        
        # 🆕 Llama a la limpieza si estaba activo el modo temporal al salir
        if self.is_temporal_mode.get():
            cleanup_multidesk(is_host=self.is_host)
            messagebox.showinfo("Limpieza", "El contenido temporal de MultiDesk ha sido eliminado.")
            
        # 🆕 Restablece el estado de host
        self.is_host = False 
        
        for widget in self.root.winfo_children():
            widget.destroy()
            
        tk.Label(self.root, text='MultiDesk', font=('Arial', 18)).pack(pady=10)
        
        # 🆕 Checkbox de Modo Temporal
        tk.Checkbutton(self.root, text="Modo Temporal (Eliminar archivos al cerrar)", variable=self.is_temporal_mode, 
                       font=('Arial', 10), fg='orange').pack(pady=5)
     
        tk.Button(self.root, text='Hostear sala', width=20, command=self.host_room).pack(pady=5)
        tk.Button(self.root, text='Conectarse a sala', width=20, command=self.connect_room).pack(pady=5)
        
        # Botón de accesibilidad y Label de visualización
        tk.Button(self.root, text='Mostrar mi dirección IP', width=40, command=self.get_my_ip_for_sharing, bg='#FF4500').pack(pady=10)
        self.ip_display_label = tk.Label(self.root, text='', font=('Arial', 10, 'bold'))
        self.ip_display_label.pack(pady=2)
        
        tk.Button(self.root, text='Registrar usuario', width=20, 
        command=self.show_register_dialog).pack(pady=5)
          
        
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
        # 🆕 Ajusta la geometría para dar espacio al botón de info
        dialog.geometry("350x180")
        dialog.transient(self.root)
        dialog.grab_set()

        # Frame para la contraseña y el botón de info
        pass_frame = tk.Frame(dialog)
        pass_frame.pack(pady=5)

        tk.Label(dialog, text="Usuario:").pack(pady=5)
        user_entry = tk.Entry(dialog)
        user_entry.pack()
        if username: user_entry.insert(0, username)
        
        tk.Label(pass_frame, text="Contraseña:").pack(side=tk.LEFT)
        pass_entry = tk.Entry(pass_frame, show='*')
        pass_entry.pack(side=tk.LEFT, padx=(0, 5))
        if password: pass_entry.insert(0, password)
        
        # 🆕 Botón de información
        info_button = tk.Button(pass_frame, text="ⓘ", 
                                command=self.show_password_requirements, 
                                relief=tk.FLAT)
        info_button.pack(side=tk.LEFT)

        def register_action():
            user = user_entry.get()
            passwd = pass_entry.get()
            
            # 🆕 Realiza la validación de complejidad de la contraseña aquí
            success, msg = self.register_user_with_complexity(user, passwd)
            
            if success:
                messagebox.showinfo("Éxito", msg)
                dialog.destroy()
            else:
                messagebox.showerror("Error", msg)

        tk.Button(dialog, text="Registrar", command=register_action).pack(pady=10)
        self.root.wait_window(dialog)

    # 🆕 Nuevo método para mostrar los requisitos de la contraseña
    def show_password_requirements(self):
        messagebox.showinfo(
            "Requisitos de Contraseña",
            "La contraseña debe cumplir con lo siguiente:\n\n"
            "1. Al menos 4 caracteres de longitud.\n"
            "2. Contener al menos una letra mayúscula.\n"
            "3. Contener al menos una letra minúscula.\n"
            "4. Contener al menos un número.\n"
            "5. Contener al menos un símbolo (!@-_)."
        )

    # 🆕 Nuevo método que envuelve el registro con una verificación de complejidad
    def register_user_with_complexity(self, username, password):
        if not username or not password:
         return False, "El nombre de usuario y la contraseña no pueden estar vacíos."
        
        # 2. Validación de Complejidad (Mayúsculas, Minúsculas, Números, Símbolos)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        # Símbolos permitidos: !@-_
        allowed_symbols = "!@-_"
        has_symbol = any(c in allowed_symbols for c in password)
        
        if not all([has_upper, has_lower, has_digit, has_symbol]):
            self.show_password_requirements() # Muestra los requisitos al fallar
            return False, "La contraseña no cumple con los requisitos de complejidad."

        # 3. Si la complejidad es correcta, procede con el registro original
        # Aquí reutilizamos el método 'register_user' pero sin la validación de longitud, 
        # que ahora se maneja arriba.
        
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            h_password = self._hash_password(password)
            
            # El código original verificaba la longitud aquí, la removemos.
            # if len(password) < 4: return False, "La contraseña debe tener al menos 4 caracteres." 
            
            cursor.execute("INSERT INTO Usuarios (username, password_hash) VALUES (?, ?)", (username, h_password))
            conn.commit()
            conn.close()
            self.current_user = username
            return True, "Registro exitoso."
        except sqlite3.IntegrityError:
            return False, "El usuario ya existe. El nombre de usuario debe ser único."
        except Exception as e:
            return False, f"Error: {e}"

    # --- [ HOST / CLIENTE ] ---
    def host_room(self):
        if not self._ask_credentials_and_authenticate():
            return
            
        # 🆕 1. Verificar si el directorio MultiDesk ya existe.
        multidesk_existed = os.path.exists(MULTIDESK_DIR)
        
        # 2. Si no existe, lo creamos.
        if not multidesk_existed:
            os.makedirs(MULTIDESK_DIR)
        
        # 🆕 3. Si el directorio ya existía, realizamos el chequeo de archivos previos.
        #    (Si fue recién creado, no hay archivos previos, evitamos el chequeo innecesario).
        if multidesk_existed:
            self._check_and_prompt_previous_files()
        
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
            "¿Quieres ingresar un puerto diferente para intentar hostear la sala de nuevo?"
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


    # --- [ Funciones de Hosteo ] ---

    # 🆕 Nuevo método para avisar al Host sobre archivos previos.
    def _check_and_prompt_previous_files(self):
        """Revisa si hay archivos remanentes en MultiDesk y pregunta si desea eliminarlos."""
        EXCLUDED_FILES = {os.path.basename(UPLOAD_LOG_FILE), os.path.basename(DB_NAME)}
        
        # Obtener lista de archivos a eliminar (no logs, no DB)
        previous_files = []
        for fname in os.listdir(MULTIDESK_DIR):
            filepath = os.path.join(MULTIDESK_DIR, fname)
            if os.path.isfile(filepath) and not fname.startswith('.') and fname not in EXCLUDED_FILES:
                previous_files.append(fname)

        if previous_files:
            file_count = len(previous_files)
            
            # Formatear la lista para mostrar en el mensaje
            file_list_str = "\n".join(previous_files[:5])
            if file_count > 5:
                file_list_str += f"\n... y {file_count - 5} más."
                
            confirm = messagebox.askyesno(
                "Archivos Previos Detectados",
                f"Se detectaron {file_count} archivo(s) de una sesión anterior en la carpeta MultiDesk:\n\n"
                f"{file_list_str}\n\n"
                "Si no los elimina, serán visibles para los clientes de esta nueva sala.\n"
                "¿Desea eliminar estos archivos de la carpeta MultiDesk antes de hostear la nueva sala?"
            )
            
            if confirm:
                files_deleted = cleanup_multidesk(is_host=True)
                # Si se eliminan archivos, también se debe vaciar el historial de subidas
                self.upload_history = {}
                self.save_upload_history() 
                messagebox.showinfo("Limpieza Exitosa", f"Se eliminaron {files_deleted} archivos anteriores.")

        # Devuelve el control para que la función host_room continúe
        return

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
            mode_text = "(Temporal)" if self.is_temporal_mode.get() else "(Persistente)"
            self.room_title_var.set(f'Sala: {self.current_user} (HOST {mode_text}) | Puerto: {self.port}')
        else:
            self.room_title_var.set(f'Sala: (Cliente) - {self.current_user} | Puerto: {self.port}')

        tk.Label(top_frame, textvariable=self.room_title_var, font=('Arial', 16)).pack(side=tk.LEFT)
        
        if self.is_host:
            tk.Button(top_frame, text='Panel de Control', command=self.open_control_panel, bg='lightblue').pack(side=tk.RIGHT)
        
        # Botones de control
        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=5)
        
        tk.Button(control_frame, text='Seleccionar Archivo (Subir)', command=self.select_file).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text='Diagnóstico', command=self.open_debug_panel, bg='lightgray').pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text='Salir', command=self.leave_room).pack(side=tk.LEFT, padx=5)
        
        # 🆕 Botones de gestión de archivos (Cliente/Descarga)
        file_action_frame = tk.Frame(self.root)
        file_action_frame.pack(pady=5)
        tk.Button(file_action_frame, text='⬇️ Descargar Archivo Seleccionado', command=self.download_selected_file, bg='lightgreen').pack(side=tk.LEFT, padx=5)
        if not self.is_host:
            tk.Button(file_action_frame, text='🗑️ Eliminar Mi Subida', command=self.client_delete_file, fg='red').pack(side=tk.LEFT, padx=5)
        
        # Etiqueta de la lista de archivos
        tk.Label(self.root, text='Lista de Archivos Compartidos (No descargados localmente):', font=('Arial', 10, 'bold')).pack(pady=(10, 0))

        self.files_listbox = tk.Listbox(self.root, width=70)
        self.files_listbox.pack()
        # 🆕 Desactiva el doble click para abrir automáticamente, se usa el botón de descarga
        # self.files_listbox.bind('<Double-Button-1>', self.open_selected_file) 
        self.update_files()
            
    def open_control_panel(self):
        HostControlPanel(self.root, self)

    # CÓDIGO MODIFICADO PARA leave_room (Asegura que siempre llama a setup_main_menu)
    def leave_room(self):
        if not self.is_host and self.host_ip:
            # Cliente notifica al Host que se va
            self.client_updater_running = False
            self.update_debug_info("Notificando al host de la desconexión...")
            try:
                headers = {'X-Username': self.current_user, 'X-Client-Ip': self.local_ip}
                self.session.delete(f'http://{self.host_ip}:{self.port}/leave', headers=headers, timeout=2)
            except requests.exceptions.RequestException:
                pass # El host ya puede estar cerrado, ignorar errores de conexión
            
        if self.is_host:
            # Limpieza para el HOST: Apagar el servidor completamente
            if self.server:
                # El server.closed flag se establece en HostControlPanel.close_room (si se usa)
                self.server.closed = True 
                # El shutdown debe ejecutarse en un hilo separado ya que bloquea el hilo principal
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                self.server = None # Limpiar la referencia
                self.update_debug_info("Servidor detenido.", is_error=False)
        
        # Limpieza de estado y retorno al menú principal
        self.port = 8000
        self.host_ip = ''
        self.setup_main_menu() # setup_main_menu maneja la limpieza temporal al volver al menú
    
    #Método para el cierre total de la aplicación (WM_DELETE_WINDOW)
    def close_application(self):
        """Maneja el cierre de la ventana principal, asegurando que cualquier sesión activa se detenga."""
        
        # 1. Ejecutar la lógica de limpieza de sesión (Host o Cliente)
        # Replicamos la lógica esencial de leave_room pero sin la parte de volver al menú.
        
        # Limpieza de Cliente
        if not self.is_host and self.host_ip:
            self.client_updater_running = False
            try:
                headers = {'X-Username': self.current_user, 'X-Client-Ip': self.local_ip}
                # Notifica al host antes de cerrar (timeout muy bajo)
                self.session.delete(f'http://{self.host_ip}:{self.port}/leave', headers=headers, timeout=1) 
            except requests.exceptions.RequestException:
                pass # Ignorar si la conexión falla

        # Limpieza de Host
        if self.is_host:
            if self.server:
                self.server.closed = True 
                # El shutdown debe ejecutarse en un hilo separado para NO CONGELAR la UI 
                # justo antes de la destrucción final.
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                self.server = None
        
        # 2. Limpieza final de archivos en modo temporal
        if self.is_temporal_mode.get():
            cleanup_multidesk(is_host=self.is_host)
        
        # 3. Forzar el cierre de la ventana principal, terminando mainloop()
        self.root.destroy()

    def force_client_leave(self, reason="El Host cerró la sala."):
        self.client_updater_running = False
        messagebox.showerror('Desconexión', reason)
        self.root.after(0, self.setup_main_menu)

    def fetch_and_update_client_files(self):
        """Hilo cliente: consulta al Host para la lista de archivos y actualiza la UI."""
        self.client_updater_running = True
        
        while self.client_updater_running:
            if not self.host_ip:
                self.client_updater_running = False
                break
                
            try:
                # Usamos el nombre actual (puede ser el original o ya desambiguado)
                headers = {'X-Username': self.current_user, 'X-Client-Ip': self.local_ip}
                response = self.session.get(f'http://{self.host_ip}:{self.port}/files_list', headers=headers, timeout=5)
                
                if response.status_code == 200:
                    # 🆕 Recuperar el nombre de usuario desambiguado del Host
                    resolved_username_encoded = response.headers.get('X-Username-Resolved')
                    if resolved_username_encoded:
                        # Si el Host nos dio un nombre único (ej: Juan 1), lo usamos
                        new_current_user = urllib.parse.unquote(resolved_username_encoded)
                        if new_current_user != self.current_user:
                             self.update_debug_info(f"Nombre actualizado por el Host a: {new_current_user}")
                             self.current_user = new_current_user
                        
                    data = response.json()
                    new_files = data.get('files', [])
                    self.host_name = data.get('host_name', 'Host Desconocido')
                    
                    # Comprueba si la lista ha cambiado (optimizando la actualización de la UI)
                    if new_files != self.files_list:
                        self.files_list = new_files
                        self.root.after(0, self._update_client_files_ui)
                        
                elif response.status_code == 401:
                    self.client_updater_running = False
                    self.root.after(0, lambda: messagebox.showerror("Conexión Fallida", "No se pudo autenticar con el Host. Verifique sus credenciales."))
                    self.root.after(0, self.setup_main_menu)
                    
                else:
                    # Esto incluye 404 si el host ya no sirve /files_list
                    self.update_debug_info(f"Host respondió con status {response.status_code}", is_error=True)
                    
            except requests.exceptions.RequestException as e:
                self.client_updater_running = False
                self.root.after(0, lambda: messagebox.showerror("Conexión Terminada", f"El Host ha cerrado la conexión o no responde."))
                self.root.after(0, self.setup_main_menu)
                break
            except Exception as e:
                self.update_debug_info(f"Error inesperado en el hilo de actualización: {e}", is_error=True)

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

    # --- [ Descarga y Eliminación de Archivos (Cliente) ] ---
    def download_selected_file(self):
        try:
            # 1. Obtiene el nombre real del archivo
            selected_indices = self.files_listbox.curselection()
            if not selected_indices:
                messagebox.showinfo("Error", "Selecciona un archivo para descargar.")
                return

            text = self.files_listbox.get(selected_indices[0])
            # Extrae solo el nombre del archivo (antes del primer espacio)
            filename = text.split(' ')[0] 
            
            # 2. Verifica si ya existe localmente
            dest_path = os.path.join(MULTIDESK_DIR, filename)
            if os.path.exists(dest_path):
                confirm = messagebox.askyesno("Confirmar Sobreescritura", 
                                              f"El archivo '{filename}' ya existe localmente.\n¿Deseas descargarlo de nuevo y sobreescribir la versión local?")
                if not confirm:
                    return

            # 3. Descarga
            url = f'http://{self.host_ip}:{self.port}/{urllib.parse.quote(filename)}'
            self.update_debug_info(f"Iniciando descarga de {filename}...")
            r = self.session.get(url, timeout=30)
            r.raise_for_status()

            with open(dest_path, 'wb') as f:
                f.write(r.content)
            
            messagebox.showinfo("Descarga Exitosa", f"'{filename}' descargado correctamente a la carpeta MultiDesk.")
            self.update_debug_info(f"Descarga de {filename} completada.")
            self.update_files() # Actualiza la lista para mostrar el tag "(Local)"

        except requests.exceptions.RequestException as e:
            self.update_debug_info(f"Error de descarga: {e}", is_error=True)
            messagebox.showerror("Error de Descarga", f"Fallo la descarga o el archivo no existe en el Host: {e}")
        except Exception as e:
            self.update_debug_info(f"Error inesperado: {e}", is_error=True)
            messagebox.showerror("Error", f"Error inesperado: {e}")

    def client_delete_file(self):
        """Permite al cliente eliminar un archivo que haya subido, en el Host."""
        if self.is_host:
            return # El host usa el Panel de Control

        try:
            # 1. Obtiene el nombre real del archivo
            selected_indices = self.files_listbox.curselection()
            if not selected_indices:
                messagebox.showinfo("Error", "Selecciona un archivo de la lista para eliminar.")
                return

            text = self.files_listbox.get(selected_indices[0])
            filename = text.split(' ')[0] 
            
            if not messagebox.askyesno("Confirmar Eliminación", 
                                        f"¿Estás seguro de que quieres solicitar al Host la eliminación de tu archivo '{filename}'?\n\nSolo el uploader puede eliminar un archivo."):
                return
            
            # 2. Solicita al Host la eliminación
            url = f'http://{self.host_ip}:{self.port}/delete_file'
            headers = {
                'X-Username': self.current_user, 
                'X-Client-Ip': self.local_ip,
                'X-Filename': urllib.parse.quote(filename)
            }
            
            self.update_debug_info(f"Solicitando al Host la eliminación de {filename}...")
            r = self.session.delete(url, headers=headers, timeout=5)
            r.raise_for_status() # Lanza error si el código no es 2xx

            # 3. Éxito: Elimina la versión local (si existe)
            local_path = os.path.join(MULTIDESK_DIR, filename)
            if os.path.exists(local_path):
                os.remove(local_path)
            
            messagebox.showinfo("Éxito", f"'{filename}' fue eliminado del Host y de tu carpeta local.")
            self.update_debug_info(f"Eliminación de {filename} confirmada por el Host.")
            
        except requests.exceptions.HTTPError as e:
            # Captura errores como 403 Forbidden (no es el uploader)
            error_message = f"Error al eliminar: {e}"
            if e.response.status_code == 403:
                 error_message = "No autorizado. Solo puedes eliminar tus propias subidas."
            messagebox.showerror("Error de Eliminación", error_message)
            self.update_debug_info(f"Fallo al eliminar {filename} (HTTP {e.response.status_code}): {e}", is_error=True)
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error de Conexión", f"Fallo de conexión con el Host: {e}")
            self.update_debug_info(f"Fallo de conexión en DELETE: {e}", is_error=True)
        except Exception as e:
            self.update_debug_info(f"Error inesperado: {e}", is_error=True)
            messagebox.showerror("Error", f"Error inesperado: {e}")


if __name__ == "__main__":
    if not os.path.exists(MULTIDESK_DIR):
        os.makedirs(MULTIDESK_DIR)
    root = tk.Tk()
    app = MultiDeskApp(root)
    root.protocol("WM_DELETE_WINDOW", app.close_application)
    root.mainloop()