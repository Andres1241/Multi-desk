import http.server
import socketserver
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import threading
import shutil
import sys
import webbrowser
import requests
import urllib.parse
from bs4 import BeautifulSoup 


PORT = 8000
MULTIDESK_DIR = os.path.join(os.getcwd(), 'MultiDesk')


# Linux y Windows
def open_file(filepath):
    """Abre un archivo usando el programa predeterminado del sistema operativo."""
    if sys.platform.startswith('darwin'):
        os.system(f'open "{filepath}"')
    elif os.name == 'nt':
        os.startfile(filepath)
    elif os.name == 'posix':
        os.system(f'xdg-open "{filepath}"')


# Servidor con autenticación básica de "sala"
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
        if ip in self.allowed_clients or not self.allowed_clients:
            print(f"[DEBUG] Conexión permitida de: {ip}")
            self.participants.add(ip)
            return True
        print(f"[DEBUG] Conexión rechazada de: {ip}")
        return False


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, app_instance=None, base_dir=None, **kwargs):
        self.base_dir = base_dir or MULTIDESK_DIR
        self.app = app_instance 
        super().__init__(*args, **kwargs)

    def do_GET(self):
        ip = self.client_address[0]
        local_path = urllib.parse.unquote(self.path.lstrip('/'))
        file_path = os.path.join(self.base_dir, local_path)
        
        if self.path == '/status':
            if hasattr(self.server, 'closed') and self.server.closed:
                self.send_response(200); self.send_header("Content-type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status":"closed"}')
            else:
                self.send_response(200); self.send_header("Content-type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status":"open"}')
        elif self.path == '/':
            self.send_response(200); self.send_header("Content-type", "text/html"); self.end_headers()
            files = os.listdir(self.base_dir)
            html = "<html><body><h2>Archivos disponibles</h2><ul>"
            for fname in files:
                html += f'<li><a href="{fname}">{fname}</a></li>'
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
        try:
            length = int(self.headers['Content-Length'])
            field_data = self.rfile.read(length)
            fname = self.headers.get('X-Filename')
            
            if fname:
                file_path = os.path.join(self.base_dir, fname)
                with open(file_path, 'wb') as f:
                    f.write(field_data)
                
                if self.app and self.app.is_host:
                    self.app.on_file_received(fname)
                    
                self.send_response(200); self.end_headers()
                self.wfile.write(b'OK')
            else:
                self.send_error(400, "No filename provided")
        except Exception as e:
            print(f"[ERROR POST] {e}")
            self.send_error(500, f"Error interno: {e}")


class MultiDeskApp:
    def __init__(self, root):
        self.root = root
        self.root.title('MultiDesk')
        self.is_host = False
        self.server_thread = None
        self.server = None
        self.allowed_clients = set()
        self.client_socket = None
        self.host_ip = ''
        self.debug_label = None
        self.files_listbox = None 
        self.last_files = set() 
        # 🔑 CORRECCIÓN 1: Crear una sesión para conexiones persistentes
        self.session = requests.Session() 
        self.setup_main_menu()

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

    def host_room(self):
        if not os.path.exists(MULTIDESK_DIR):
            os.makedirs(MULTIDESK_DIR)
        self.is_host = True
        self.allowed_clients = set()
        self.start_server()
        self.show_room_window()

        if self.debug_label:
            self.debug_label.config(text='[DEBUG] Hosteando sala en puerto {}...'.format(PORT))

    def connect_room(self):
        ip = simpledialog.askstring('Conectar', 'Ingrese la IP del host:')
        if ip:
            self.host_ip = ip
            self.is_host = False
            self.connect_to_server(ip)
            self.show_room_window()
            if self.debug_label:
                self.debug_label.config(text=f'[DEBUG] Intentando conectar a {ip}:{PORT}...')
    
    def start_server(self):
        def run_server():
            handler = lambda *args, **kwargs: CustomHandler(*args, app_instance=self, base_dir=MULTIDESK_DIR, **kwargs)
            self.server = AuthTCPServer(("0.0.0.0", PORT), handler, self.allowed_clients)
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
        self.allowed_clients.add('dummy')
        
    def update_files(self):
        """Actualiza el Listbox y programa el siguiente refresco."""
        if self.files_listbox:
            self.files_listbox.delete(0, tk.END)
            files = os.listdir(MULTIDESK_DIR)
            for fname in sorted(files):
                self.files_listbox.insert(tk.END, fname)
            
            self.last_files = set(files)
        
        try:
            if self.root.winfo_exists() and (not self.server or not self.server.closed):
                self.root.after(2000, self.update_files) 
        except Exception:
            pass
    
    def _ask_to_open_file_core(self, filename):
        """Contiene la lógica de GUI: el pop-up de confirmación y apertura."""
        
        # 1. Actualizar Listbox y la lista de archivos rastreados
        self.update_files() 
        
        file_path = os.path.join(MULTIDESK_DIR, filename)

        # 2. Preguntar al usuario (seguridad)
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
        
        # 3. Log
        if self.debug_label:
            self.debug_label.config(text=f'[DEBUG] Recepción y listado finalizado: {filename}')


    def on_file_received(self, filename):
        """
        Llamado por CustomHandler (hilo no-GUI) o Cliente (sincronización).
        Programa la ejecución de la confirmación en el hilo principal de Tkinter.
        """
        self.root.after(0, lambda: self._ask_to_open_file_core(filename))
    
    def show_room_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        tk.Label(self.root, text='Sala MultiDesk', font=('Arial', 16)).pack(pady=10)
        
        drop_frame = tk.LabelFrame(self.root, text='Arrastra archivos aquí', width=300, height=120)
        drop_frame.pack(padx=10, pady=10)
        drop_frame.pack_propagate(False)
        drop_frame.bind('<Button-1>', lambda e: self.select_file())
        
        tk.Button(self.root, text='Salir de la sala', command=self.leave_room).pack(pady=10)
        
        self.debug_label = tk.Label(self.root, text='', fg='blue')
        self.debug_label.pack(pady=2)
        
        files_frame = tk.LabelFrame(self.root, text='Archivos subidos')
        files_frame.pack(padx=10, pady=5)
        
        self.files_listbox = tk.Listbox(files_frame, width=40)
        self.files_listbox.pack()
        
        self.update_files() 
        
        # Sincronización (Cliente)
        def sync_with_host():
            if not self.is_host and self.host_ip:
                try:
                    status_url = f'http://{self.host_ip}:{PORT}/status'
                    sr = self.session.get(status_url, timeout=2)
                    if sr.status_code == 200 and sr.json().get('status') == 'closed':
                        self.debug_label.config(text='[DEBUG] El host cerró la sala. Saliendo...')
                        self.empty_multidesk_folder(); self.setup_main_menu()
                        return  
                    url = f'http://{self.host_ip}:{PORT}/'
                    r = self.session.get(url)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'html.parser')
                        remote_files = set([a.get('href') for a in soup.find_all('a') if a.get('href')])
                        local_files = set(os.listdir(MULTIDESK_DIR))
                        missing = remote_files - local_files
                        for fname in missing:
                            file_url = f'http://{self.host_ip}:{PORT}/{fname}'
                            dest_path = os.path.join(MULTIDESK_DIR, fname)
                            fr = self.session.get(file_url)
                            if fr.status_code == 200:
                                with open(dest_path, 'wb') as f:
                                    f.write(fr.content)
                                self.on_file_received(fname)
                except Exception as e:
                    self.debug_label.config(text=f'[DEBUG] Error de sincronización: {e}')
            self.root.after(2000, sync_with_host)
        sync_with_host()
        
        # Detección de nuevos archivos
        def check_new_files():
            current_files = set(os.listdir(MULTIDESK_DIR))
            new_files = current_files - self.last_files
            if new_files:
                for fname in new_files:
                    if self.is_host:
                        pass
                    else:
                        self.debug_label.config(text=f'[DEBUG] Archivo de Host detectado: {fname}.')
                self.last_files = current_files
            self.root.after(2000, check_new_files)
        check_new_files()
        
        if self.is_host:
            tk.Button(self.root, text='Cerrar sala', command=self.close_room).pack(pady=5)
            part_frame = tk.LabelFrame(self.root, text='Participantes conectados')
            part_frame.pack(padx=10, pady=5)
            part_list = tk.Listbox(part_frame, width=40)
            part_list.pack()
            def update_participants():
                part_list.delete(0, tk.END)
                if self.server:
                    for ip in sorted(self.server.participants):
                        part_list.insert(tk.END, ip)
                self.root.after(2000, update_participants)
            update_participants()

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.send_file(file_path)

    def send_file(self, file_path):
        dest = os.path.join(MULTIDESK_DIR, os.path.basename(file_path))
        if self.is_host:
            shutil.copy(file_path, dest)
            messagebox.showinfo('Archivo enviado', f'Se envió {os.path.basename(file_path)} a la sala.')
            self.debug_label.config(text=f'[DEBUG] Archivo enviado: {os.path.basename(file_path)}')
            self.update_files() 
        else:
            # Cliente
            try:
                file_name = os.path.basename(file_path)
                dest_path = os.path.join(MULTIDESK_DIR, file_name) # Ruta de destino local
                
                with open(file_path, 'rb') as f:
                    data = f.read()
                url = f'http://{self.host_ip}:{PORT}/'
                headers = {'X-Filename': file_name}
                
                # 🔑 USAR SESIÓN para evitar la demora de la nueva conexión
                r = self.session.post(url, data=data, headers=headers) 
                
                if r.status_code == 200:
                    # 🔑 CORRECCIÓN 2: Copiar el archivo localmente INMEDIATAMENTE
                    shutil.copy(file_path, dest_path) 
                    # 🔑 CORRECCIÓN 2: Forzar la actualización del Listbox
                    self.update_files() 
                    
                    messagebox.showinfo('Archivo enviado', f'Se envió {file_name} a la sala.')
                    self.debug_label.config(text=f'[DEBUG] Archivo subido al host: {file_name}')
                else:
                    self.debug_label.config(text=f'[DEBUG] Error al subir archivo: {r.status_code}')
            except Exception as e:
                self.debug_label.config(text=f'[DEBUG] Falló el envío: {e}')

    def leave_room(self):
        if self.is_host:
            self.close_room()
        else:
            self.empty_multidesk_folder()  
            self.setup_main_menu()
        self.debug_label.config(text='[DEBUG] Saliste de la sala.')

    def close_room(self):
        if self.server:
            self.server.closed = True
            threading.Thread(target=self.server.shutdown).start()
            self.server = None 

        self.empty_multidesk_folder()  
        self.setup_main_menu()
        self.debug_label.config(text='[DEBUG] Sala cerrada.')

    def empty_multidesk_folder(self):
        for fname in os.listdir(MULTIDESK_DIR):
            fpath = os.path.join(MULTIDESK_DIR, fname)
            try:
                if os.path.isfile(fpath):
                    os.remove(fpath)
                elif os.path.isdir(fpath):
                    shutil.rmtree(fpath)
            except Exception as e:
                print(f"[DEBUG] Error borrando {fpath}: {e}")

if __name__ == "__main__":
    if not os.path.exists(MULTIDESK_DIR):
        os.makedirs(MULTIDESK_DIR)
    root = tk.Tk()
    app = MultiDeskApp(root)
    root.mainloop()