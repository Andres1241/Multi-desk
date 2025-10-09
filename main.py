import http.server
import socketserver
import socket #
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import threading
import shutil
import sys
import urllib.parse
import requests
from bs4 import BeautifulSoup
import json # Necesario para serializar el registro de archivos




PORT = 8000
MULTIDESK_DIR = os.path.join(os.getcwd(), 'MultiDesk')
# Nuevo: Nombre del archivo de registro de subidas
UPLOAD_LOG_FILE = os.path.join(MULTIDESK_DIR, '.upload_log.json')




# --- [ FUNCIÓN AUXILIAR ] ---
def open_file(filepath):
    """Abre un archivo usando el programa predeterminado del sistema operativo."""
    if sys.platform.startswith('darwin'):  # macOS
        os.system(f'open "{filepath}"')
    elif os.name == 'nt':  # Windows
        os.startfile(filepath)
    elif os.name == 'posix':  # Linux
        os.system(f'xdg-open "{filepath}"')




# --- [ SERVIDOR Y HANDLER HTTP ] ---
class AuthTCPServer(socketserver.TCPServer):
    """Servidor TCP con reutilización de dirección y verificación básica de conexión."""
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
    """Manejador HTTP para servir archivos y recibir POSTs."""
    def __init__(self, *args, app_instance=None, base_dir=None, **kwargs):
        self.base_dir = base_dir or MULTIDESK_DIR
        self.app = app_instance
        super().__init__(*args, **kwargs)
   
    # NUEVO: Método auxiliar para obtener la IP del cliente que hace la solicitud
    def get_client_ip(self):
        """Intenta obtener la IP del cliente, priorizando el encabezado si viene de un cliente."""
        # Si el cliente envia su propia IP (desde send_file), la usamos.
        ip_from_header = self.headers.get('X-Client-Ip')
        if ip_from_header:
            return ip_from_header
        # Si no, usamos la IP de la conexión TCP (solo para peticiones GET/HEAD)
        return self.client_address[0]
       
    def do_GET(self):
        local_path = urllib.parse.unquote(self.path.lstrip('/'))
        file_path = os.path.join(self.base_dir, local_path)
       
        if self.path == '/status':
            status = 'closed' if hasattr(self.server, 'closed') and self.server.closed else 'open'
            self.send_response(200); self.send_header("Content-type", "application/json"); self.end_headers()
            self.wfile.write(f'{{"status":"{status}"}}'.encode('utf-8'))
           
        elif self.path == '/':
            self.send_response(200); self.send_header("Content-type", "text/html"); self.end_headers()
            files = os.listdir(self.base_dir)
            html = "<html><body><h2>Archivos disponibles</h2><ul>"
            for fname in files:
                if os.path.isfile(os.path.join(self.base_dir, fname)) and not fname.startswith('.'):
                    # Ignorar el archivo de log para que los clientes no lo sincronicen
                    if fname == os.path.basename(UPLOAD_LOG_FILE):
                         continue
                    html += f'<li><a href="{urllib.parse.quote(fname)}">{fname}</a></li>'
            html += "</ul></body></html>"
            self.wfile.write(html.encode('utf-8'))
           
        elif os.path.isfile(file_path):
            self.send_response(200); self.send_header("Content-type", "application/octet-stream")
            self.send_header("Content-Length", str(os.path.getsize(file_path))); self.end_headers()
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
               
        else:
            self.send_error(404)


    def do_POST(self):
        """Maneja la subida de archivos (cliente a host)."""
        try:
            length = int(self.headers['Content-Length'])
            field_data = self.rfile.read(length)
            fname = self.headers.get('X-Filename')
            client_ip = self.get_client_ip() # Obtener la IP del cliente/host
           
            if fname:
                file_path = os.path.join(self.base_dir, fname)
                with open(file_path, 'wb') as f:
                    f.write(field_data)
               
                # NUEVO: Registrar la IP de quien subió el archivo
                if self.app and self.app.is_host:
                    self.app.register_upload(fname, client_ip)
                       
                self.send_response(200); self.end_headers()
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
        self.local_ip = self._get_local_ip() # Obtener la IP local
        self.debug_label = None
        self.files_listbox = None
        self.last_files = set()
        self.selected_file_name = None
        self.upload_history = {} # NUEVO: Diccionario para historial de subidas
        self.session = requests.Session()
        self.setup_main_menu()
        self.load_upload_history() # Cargar el historial al inicio


    def _get_local_ip(self):
        """Intenta obtener la IP local del sistema."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
           
    # --- Manejo del Log de Subidas (Solo Host) ---
   
    def save_upload_history(self):
        """Guarda el historial de subidas en un archivo JSON."""
        if self.is_host:
            try:
                with open(UPLOAD_LOG_FILE, 'w') as f:
                    json.dump(self.upload_history, f, indent=4)
            except Exception as e:
                print(f"[ERROR LOG] No se pudo guardar el log de subidas: {e}")


    def load_upload_history(self):
        """Carga el historial de subidas desde el archivo JSON."""
        if os.path.exists(UPLOAD_LOG_FILE):
            try:
                with open(UPLOAD_LOG_FILE, 'r') as f:
                    self.upload_history = json.load(f)
            except Exception as e:
                print(f"[ERROR LOG] No se pudo cargar el log de subidas: {e}")
                self.upload_history = {}


    def register_upload(self, filename, ip_address):
        """Registra quién subió un archivo y guarda el log."""
        self.upload_history[filename] = ip_address
        self.save_upload_history()
        self.on_file_received(filename)


    # --- Configuración de Vistas ---


    def setup_main_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text='MultiDesk', font=('Arial', 18)).pack(pady=10)
        tk.Button(self.root, text='Hostear sala', width=20, command=self.host_room).pack(pady=5)
        tk.Button(self.root, text='Conectarse a sala', width=20, command=self.connect_room).pack(pady=5)
        if self.debug_label:
            self.debug_label.destroy()
        self.debug_label = tk.Label(self.root, text='', fg='blue')
        self.debug_label.pack(pady=2)


    def show_room_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
           
        tk.Label(self.root, text='Sala MultiDesk', font=('Arial', 16)).pack(pady=10)
       
        # Botón/Área para subir archivos
        drop_frame = tk.LabelFrame(self.root, text='Clic para Subir Archivo')
        drop_frame.pack(padx=10, pady=10)
        tk.Button(drop_frame, text='Seleccionar Archivo', command=self.select_file).pack(padx=5, pady=5)
       
        tk.Button(self.root, text='Salir de la sala', command=self.leave_room).pack(pady=10)
       
        self.debug_label = tk.Label(self.root, text='', fg='blue')
        self.debug_label.pack(pady=2)
       
        # Listado de archivos
        # MODIFICACIÓN: Listado de archivos más ancho para la IP
        files_frame = tk.LabelFrame(self.root, text='Archivos de la Sala (Doble Clic para Abrir)')
        files_frame.pack(padx=10, pady=5)
       
        # Si es Host, la lista es más ancha para mostrar la IP
        list_width = 60 if self.is_host else 40
        self.files_listbox = tk.Listbox(files_frame, width=list_width)
        self.files_listbox.pack()
       
        self.files_listbox.bind('<<ListboxSelect>>', self.on_listbox_select)
        self.files_listbox.bind('<Double-Button-1>', self.open_selected_file)
       
        self.update_files() # Primera actualización
       
        # --- Lógica de Host ---
        if self.is_host:
            tk.Button(self.root,
                      text='Eliminar Archivo Seleccionado',
                      command=self.delete_selected_file).pack(pady=5)
            tk.Button(self.root, text='Cerrar sala', command=self.close_room).pack(pady=5)
           
            # Listado de participantes (Solo Host)
            part_frame = tk.LabelFrame(self.root, text='Participantes conectados')
            part_frame.pack(padx=10, pady=5)
            part_list = tk.Listbox(part_frame, width=40)
            part_list.pack()
            def update_participants():
                part_list.delete(0, tk.END)
                if self.server:
                    for ip in sorted(self.server.participants):
                        part_list.insert(tk.END, ip)
                if self.root.winfo_exists():
                    self.root.after(2000, update_participants)
            update_participants()


        # --- Lógica de Cliente ---
        if not self.is_host:
            self.root.after(2000, self.sync_with_host)
           
        self.root.after(2000, self.check_new_files)
       
    def on_listbox_select(self, event):
        """Registra el nombre del archivo al hacer clic en el Listbox, ignorando la IP en la visualización."""
        widget = event.widget
        try:
            index = widget.curselection()[0]
            full_text = widget.get(index)
           
            # Si es Host, el nombre del archivo es el texto antes del primer espacio
            if self.is_host:
                self.selected_file_name = full_text.split(' ')[0]
            else:
                self.selected_file_name = full_text
           
            self.debug_label.config(text=f"[DEBUG] Seleccionado: {self.selected_file_name}")
        except IndexError:
            self.selected_file_name = None


    # --- Manejo de Sala (Host/Cliente) ---
   
    def host_room(self):
        if not os.path.exists(MULTIDESK_DIR):
            os.makedirs(MULTIDESK_DIR)
        self.is_host = True
        self.load_upload_history() # Asegurar que el log esté cargado
        self.start_server()
        self.show_room_window()
        self.debug_label.config(text=f'[DEBUG] Hosteando sala en puerto {PORT}. IP: {self.local_ip}')


    def connect_room(self):
        ip = simpledialog.askstring('Conectar', 'Ingrese la IP del host:')
        if ip:
            self.host_ip = ip
            self.is_host = False
            self.connect_to_server(ip)
            self.show_room_window()
            self.debug_label.config(text=f'[DEBUG] Intentando conectar a {ip}:{PORT}...')
   
    def leave_room(self):
        if self.is_host:
            self.close_room()
        else:
            self.empty_multidesk_folder()
            self.setup_main_menu()
        self.debug_label.config(text='[DEBUG] Saliste de la sala.')


    def close_room(self):
        """Cierra el servidor (Solo Host) y notifica a los clientes."""
        if self.server:
            self.server.closed = True
            threading.Thread(target=self.server.shutdown).start()
            self.server = None
       
        # Eliminar el log y limpiar la carpeta solo si el host la cierra
        if os.path.exists(UPLOAD_LOG_FILE):
             os.remove(UPLOAD_LOG_FILE)
        self.empty_multidesk_folder()
        self.setup_main_menu()
        self.debug_label.config(text='[DEBUG] Sala cerrada.')


    def empty_multidesk_folder(self):
        """Borra todos los archivos dentro del directorio MultiDesk, excepto el archivo de log si existe."""
        for fname in os.listdir(MULTIDESK_DIR):
            fpath = os.path.join(MULTIDESK_DIR, fname)
            # NUEVO: Ignorar el archivo de log para que no se borre si es un host que quiere mantener el log
            if fname == os.path.basename(UPLOAD_LOG_FILE):
                continue
            try:
                if os.path.isfile(fpath):
                    os.remove(fpath)
            except Exception as e:
                print(f"[DEBUG] Error borrando {fpath}: {e}")


    # --- Lógica de Servidor/Cliente y Sincronización ---
   
    # ... (start_server, connect_to_server, sync_with_host son iguales) ...


    def start_server(self):
        def run_server():
            handler = lambda *args, **kwargs: CustomHandler(*args, app_instance=self, base_dir=MULTIDESK_DIR, **kwargs)
            self.server = AuthTCPServer(("0.0.0.0", PORT), handler, set()) # 'allowed_clients' no se usa
            self.server.app_instance = self
            print(f"Servidor iniciado")
            self.server.serve_forever()
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()


    def connect_to_server(self, ip):
        try:
            url = f'http://{ip}:{PORT}/'
            r = self.session.get(url, timeout=3)
            if r.status_code == 200 or r.status_code == 404:
                self.debug_label.config(text=f'[DEBUG] Conectado a sala en {ip}')
            else:
                self.debug_label.config(text=f'[DEBUG] Error al conectar ({r.status_code})')
        except requests.exceptions.ConnectionError:
            self.debug_label.config(text=f'[DEBUG] No se pudo conectar: sala no existe o IP incorrecta')
        except Exception as e:
            self.debug_label.config(text=f'[DEBUG] Falló la conexión: {e}')
       
    def sync_with_host(self):
        """[Cliente] Sincroniza archivos con el host (descarga faltantes, borra eliminados)."""
        if not self.is_host and self.host_ip:
            try:
                # 1. Verificar el estado del host (si cerró la sala)
                status_url = f'http://{self.host_ip}:{PORT}/status'
                sr = self.session.get(status_url, timeout=2)
                if sr.status_code == 200 and sr.json().get('status') == 'closed':
                    self.debug_label.config(text='[DEBUG] El host cerró la sala. Saliendo...')
                    self.empty_multidesk_folder(); self.setup_main_menu()
                    return
                   
                # 2. Obtener la lista de archivos del host
                url = f'http://{self.host_ip}:{PORT}/'
                r = self.session.get(url)
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'html.parser')
                    remote_files = set([urllib.parse.unquote(a.get('href')) for a in soup.find_all('a') if a.get('href')])
                    local_files = set(os.listdir(MULTIDESK_DIR))
                   
                    # Limpieza: Borrar archivos eliminados por el host
                    files_to_delete = local_files - remote_files
                    for fname in files_to_delete:
                        file_to_delete = os.path.join(MULTIDESK_DIR, fname)
                        if os.path.isfile(file_to_delete):
                            os.remove(file_to_delete)
                            self.debug_label.config(text=f'[DEBUG] Archivo limpiado: {fname}.')
                   
                    # 3. Descargar archivos faltantes
                    missing = remote_files - local_files
                    for fname in missing:
                        if fname in files_to_delete: continue
                       
                        file_url = f'http://{self.host_ip}:{PORT}/{urllib.parse.quote(fname)}'
                        dest_path = os.path.join(MULTIDESK_DIR, fname)
                       
                        fr = self.session.get(file_url, stream=True)
                        if fr.status_code == 200:
                            with open(dest_path, 'wb') as f:
                                for chunk in fr.iter_content(chunk_size=8192):
                                    f.write(chunk)
                            self.on_file_received(fname)
                           
                self.update_files()
            except requests.exceptions.ConnectionError:
                self.debug_label.config(text=f'[DEBUG] Conexión perdida con el host.')
            except Exception as e:
                self.debug_label.config(text=f'[DEBUG] Error de sincronización: {e}')
               
        if self.root.winfo_exists():
            self.root.after(2000, self.sync_with_host)


    def update_files(self):
        """Actualiza el Listbox con los archivos locales. Incluye IP si es Host."""
        if self.files_listbox:
            self.files_listbox.delete(0, tk.END)
            files = os.listdir(MULTIDESK_DIR)
           
            # Filtrar archivos no deseados
            filtered_files = sorted([f for f in files if not f.startswith('.') and f != os.path.basename(UPLOAD_LOG_FILE)])
           
            for fname in filtered_files:
                display_name = fname
               
                # NUEVO: Mostrar la IP solo si es el Host
                if self.is_host:
                    uploader_ip = self.upload_history.get(fname, 'DESCONOCIDA')
                    display_name = f"{fname:<30} (Subido por: {uploader_ip})"
               
                self.files_listbox.insert(tk.END, display_name)
           
            self.last_files = set(filtered_files)
       
        try:
            if self.root.winfo_exists() and (not self.server or not self.server.closed):
                self.root.after(2000, self.update_files)
        except Exception:
            pass
           
    # ... (check_new_files, on_file_received, _ask_to_open_file_core son iguales) ...
    def check_new_files(self):
        """Verifica si el Host/Cliente añadió un archivo localmente."""
        current_files = set(os.listdir(MULTIDESK_DIR))
        # Quitar el log del set de archivos
        current_files.discard(os.path.basename(UPLOAD_LOG_FILE))
       
        new_files = current_files - self.last_files
       
        if new_files:
            for fname in new_files:
                self.debug_label.config(text=f'[DEBUG] Archivo local detectado: {fname}.')
            self.last_files = current_files
            self.update_files()
           
        if self.root.winfo_exists():
            self.root.after(2000, self.check_new_files)


    def on_file_received(self, filename):
        """Llamado en recepción de archivo (POST o GET en cliente). Muestra el pop-up."""
        self.root.after(0, lambda: self._ask_to_open_file_core(filename))
   
    def _ask_to_open_file_core(self, filename):
        """Lógica de GUI: pop-up de confirmación y apertura de archivo."""
       
        self.update_files()
        file_path = os.path.join(MULTIDESK_DIR, filename)


        if self.is_host:
             self.debug_label.config(text=f'[DEBUG] Recepción local finalizada: {filename}')
             return


        confirm = messagebox.askyesno(
            "Archivo Recibido",
            f"Has recibido el archivo '{filename}'.\n\n¿Deseas abrirlo ahora?",
            icon=messagebox.QUESTION
        )


        if confirm:
            try:
                open_file(file_path)
                self.debug_label.config(text=f'[DEBUG] Archivo {filename} abierto.')
            except Exception as e:
                messagebox.showerror("Error de Apertura", f"No se pudo abrir el archivo: {e}")


    # --- Acciones de Usuario ---


    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.send_file(file_path)


    def send_file(self, file_path):
        """Envía el archivo (Cliente -> Host) o copia localmente (Host)."""
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(MULTIDESK_DIR, file_name)


        if self.is_host:
            # Host: Copia localmente y se auto-registra
            shutil.copy(file_path, dest_path)
            self.register_upload(file_name, self.local_ip) # Se registra con su propia IP
            messagebox.showinfo('Archivo enviado', f'Se agregó {file_name} a la sala.')
            self.debug_label.config(text=f'[DEBUG] Archivo añadido al host: {file_name}')
           
        else:
            # Cliente: Sube al Host. Incluye su IP en el encabezado
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                url = f'http://{self.host_ip}:{PORT}/'
               
                # NUEVO: Encabezado con la IP del cliente
                headers = {'X-Filename': file_name, 'X-Client-Ip': self.local_ip}
               
                r = self.session.post(url, data=data, headers=headers)
               
                if r.status_code == 200:
                    shutil.copy(file_path, dest_path)
                    self.update_files()
                   
                    messagebox.showinfo('Archivo enviado', f'Se subió {file_name} a la sala.')
                    self.debug_label.config(text=f'[DEBUG] Archivo subido al host: {file_name}')
                else:
                    self.debug_label.config(text=f'[DEBUG] Error al subir archivo: {r.status_code}')
            except Exception as e:
                self.debug_label.config(text=f'[DEBUG] Falló el envío: {e}')


    def open_selected_file(self, event):
        """Abre el archivo seleccionado (usando la variable de estado)."""
        filename = self.selected_file_name
       
        if not filename: return


        file_path = os.path.join(MULTIDESK_DIR, filename)


        if not os.path.exists(file_path):
            messagebox.showerror("Error", "El archivo no existe localmente.")
            return


        try:
            open_file(file_path)
            self.debug_label.config(text=f'[DEBUG] Abriendo: {filename}')
        except Exception as e:
            messagebox.showerror("Error de Apertura", f"No se pudo abrir el archivo: {e}")


    def delete_selected_file(self):
        """[Host] Elimina un archivo seleccionado del directorio y de la sala."""
        if not self.is_host:
            messagebox.showerror("Error", "Solo el Host puede eliminar archivos.")
            return
           
        filename = self.selected_file_name
       
        if not filename:
            messagebox.showwarning("Advertencia", "Por favor, selecciona un archivo de la lista para eliminar (haciendo clic).")
            return
           
        file_path = os.path.join(MULTIDESK_DIR, filename)


        if messagebox.askyesno("Confirmar Eliminación",
                               f"¿Estás seguro de que quieres **ELIMINAR PERMANENTEMENTE** el archivo '{filename}' de la sala?\n\n(Esto lo borrará para todos los participantes).",
                               icon='warning'):
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                   
                    # NUEVO: Eliminar el registro del historial
                    if filename in self.upload_history:
                        del self.upload_history[filename]
                        self.save_upload_history()
                       
                    self.update_files()
                    self.selected_file_name = None
                    self.debug_label.config(text=f'[DEBUG] Archivo eliminado por el host: {filename}')
                    messagebox.showinfo("Éxito", f"'{filename}' ha sido eliminado de la sala.")
                else:
                    messagebox.showerror("Error", "No se encontró el archivo localmente.")
                   
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo completar la eliminación: {e}")




if __name__ == "__main__":
    if not os.path.exists(MULTIDESK_DIR):
        os.makedirs(MULTIDESK_DIR)
    root = tk.Tk()
    app = MultiDeskApp(root)
    root.protocol("WM_DELETE_WINDOW", app.leave_room)
    root.mainloop()