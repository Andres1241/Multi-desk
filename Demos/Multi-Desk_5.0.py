import http.server
import socketserver
import socket
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, Toplevel
# Optional drag & drop backends. We try to support multiple implementations
# so the Multi-Square can accept files dragged from the OS file explorer.
try:
    from tkinterdnd2 import DND_FILES
    TKDND_AVAILABLE = True
except Exception:
    DND_FILES = None
    TKDND_AVAILABLE = False

try:
    import windnd
    WINDND_AVAILABLE = True
except Exception:
    WINDND_AVAILABLE = False
import tkinter.ttk as ttk
import threading
import shutil
import sys
import random
import json
import urllib.parse
import hashlib
import sqlite3
import requests
import time

# --- [ CONFIGURACIÓN GLOBAL ] ---
MULTIDESK_DIR = os.path.join(os.getcwd(), 'MultiDesk')
UPLOAD_LOG_FILE = os.path.join(MULTIDESK_DIR, '.upload_log.json')
DB_NAME = os.path.join(os.getcwd(), 'multidesk.db')
FILE_UPDATE_INTERVAL = 5000 # 5 segundos
HOST_SYSTEM_NAME = socket.gethostname()

# --- [ DICCIONARIO DE TRADUCCIONES ] ---
TRANSLATIONS = {
    'es': {
        # Configuración
        'config_title': 'Configuración de MultiDesk',
        'temporal_mode': 'Modo Temporal',
        'enable_temporal': 'Activar modo temporal',
        'temporal_desc': 'Los archivos se eliminarán al cerrar la sala',
        'multi_square': 'Multi-Square',
        'enable_multi_square': 'Activar Multi-Square',
        'size': 'Tamaño:',
        'position': 'Posición:',
        'language': 'Idioma:',
        'save': 'Guardar',
        'error': 'Error',
        'integer_error': 'Los valores deben ser números enteros',
        'drag_files': 'Arrastra archivos o carpetas aquí\n(o haz doble clic)',
        'error_loading_config': 'Error cargando configuración:',
        'error_saving_config': 'Error guardando configuración:',
        
        # Menú Principal
        'title': 'MultiDesk',
        'host_room': 'Hostear sala',
        'connect_room': 'Conectarse a sala',
        'register_user': 'Registrar usuario',
        'configuration': '⚙ Configuración',
        
        # Registrar Usuario
        'username': 'Usuario:',
        'password': 'Contraseña:',
        'register': 'Registrar',
        
        # Sala de Host
        'code_for_connection': 'Código de palabras para que los clientes se conecten:',
        'copy_code': 'Copiar código',
        'connected_users': 'Usuarios Conectados',
        'file_management': 'Gestión de Archivos',
        'close_room': 'Cerrar Sala',
        'active_users': 'Usuarios activos:',
        'files_in_multidesk': 'Archivos en MultiDesk (Selección múltiple con Ctrl/Shift):',
        'delete_selected': 'Eliminar Seleccionados',
        'delete_all_files': 'Eliminar TODOS los Archivos',
        'delete_file': 'BORRAR ARCHIVO',
        
        # Sala de Cliente
        'control_panel': 'Panel de Control',
        'select_file_upload': 'Seleccionar Archivo o Carpeta (Subir)',
        'diagnostics': 'Diagnóstico',
        'leave': 'Salir',
        'download_selected': '⬇️ Descargar Archivo Seleccionado',
        'delete_my_upload': '🗑️ Eliminar Mi Subida',
        'shared_files': 'Lista de Archivos Compartidos (No descargados localmente):',
        'local_ip': 'Tu dirección IP local es:',
        
        # Panel de Diagnóstico
        'diagnostic_title': 'Panel de Diagnóstico (Debug)',
        'diagnostic_start': '--- [ INICIO DEL DIAGNÓSTICO ] ---',
        'operating_system': 'Sistema Operativo:',
        'hostname': 'Hostname:',
        'reported_ip': 'IP Local (Reportada):',
        'multidesk_dir': 'Directorio MultiDesk:',
        
        # Alertas y Confirmaciones
        'copied': 'Copiado',
        'code_copied': 'Código copiado al portapapeles',
        'no_files_selected': 'Información',
        'no_files_selected_msg': 'No hay archivos seleccionados.',
        'could_not_delete': 'No se pudo eliminar {}: {}',
        'files_deleted': 'Éxito',
        'files_deleted_msg': 'Archivos eliminados correctamente.',
        'files_deleted_count': 'Éxito',
        'files_deleted_count_msg': 'Se eliminaron {} archivos de la sala.',
        'selection_required': 'Selección Requerida',
        'selection_required_msg': 'Por favor, selecciona un archivo para eliminar.',
        'single_selection': 'Selección Única',
        'single_selection_msg': 'Por favor, selecciona solo UN archivo para eliminar.',
        'file_not_exist': 'Error',
        'file_not_exist_msg': 'El archivo ya no existe.',
        'file_deleted': 'Éxito',
        'file_deleted_msg': 'El archivo \'{}\' fue eliminado correctamente.',
        'delete_error': 'Error',
        'delete_error_msg': 'No se pudo eliminar el archivo: {}',
        'cleanup': 'Limpieza',
        'cleanup_msg': 'Modo temporal activo: Se eliminaron {} archivos locales.',
        'cleanup_temp': 'Limpieza',
        'cleanup_temp_msg': 'El contenido temporal de MultiDesk ha sido eliminado.',
        'already_logged': 'Info',
        'already_logged_msg': 'Ya estás logueado como {}.',
        'welcome': 'Éxito',
        'welcome_msg': 'Bienvenido, {}.',
        'auto_upload': 'Auto-Upload',
        'auto_upload_msg': 'Archivo {} subido automáticamente',
        'upload_error': 'Error',
        'upload_error_msg': 'Error al subir el archivo: {}',
        
        # Mensajes generales
        'success': 'Éxito',
        'confirmation': 'Confirmación',
        'are_you_sure': '¿Estás seguro?',
        'user_registered': 'Usuario registrado exitosamente',
        'user_exists': 'El usuario ya existe',
        'invalid_credentials': 'Credenciales inválidas',
        'room_created': 'Sala creada exitosamente',
        'room_connected': 'Conectado a la sala',
        'file_uploaded': 'Archivo subido exitosamente',
        'file_downloaded': 'Archivo descargado exitosamente',
    },
    'en': {
        # Configuration
        'config_title': 'MultiDesk Configuration',
        'temporal_mode': 'Temporal Mode',
        'enable_temporal': 'Enable temporal mode',
        'temporal_desc': 'Files will be deleted when closing the room',
        'multi_square': 'Multi-Square',
        'enable_multi_square': 'Enable Multi-Square',
        'size': 'Size:',
        'position': 'Position:',
        'language': 'Language:',
        'save': 'Save',
        'error': 'Error',
        'integer_error': 'Values must be integers',
        'drag_files': 'Drag files or folders here\n(or double-click)',
        'error_loading_config': 'Error loading configuration:',
        'error_saving_config': 'Error saving configuration:',
        
        # Main Menu
        'title': 'MultiDesk',
        'host_room': 'Host Room',
        'connect_room': 'Connect to Room',
        'register_user': 'Register User',
        'configuration': '⚙ Configuration',
        
        # Register User
        'username': 'Username:',
        'password': 'Password:',
        'register': 'Register',
        
        # Host Room
        'code_for_connection': 'Word code for clients to connect:',
        'copy_code': 'Copy Code',
        'connected_users': 'Connected Users',
        'file_management': 'File Management',
        'close_room': 'Close Room',
        'active_users': 'Active Users:',
        'files_in_multidesk': 'Files in MultiDesk (Multiple selection with Ctrl/Shift):',
        'delete_selected': 'Delete Selected',
        'delete_all_files': 'Delete ALL Files',
        'delete_file': 'DELETE FILE',
        
        # Client Room
        'control_panel': 'Control Panel',
        'select_file_upload': 'Select File or Folder (Upload)',
        'diagnostics': 'Diagnostics',
        'leave': 'Leave',
        'download_selected': '⬇️ Download Selected File',
        'delete_my_upload': '🗑️ Delete My Upload',
        'shared_files': 'List of Shared Files (Not downloaded locally):',
        'local_ip': 'Your local IP address is:',
        
        # Diagnostic Panel
        'diagnostic_title': 'Diagnostic Panel (Debug)',
        'diagnostic_start': '--- [ DIAGNOSTIC START ] ---',
        'operating_system': 'Operating System:',
        'hostname': 'Hostname:',
        'reported_ip': 'Local IP (Reported):',
        'multidesk_dir': 'MultiDesk Directory:',
        
        # Alerts and Confirmations
        'copied': 'Copied',
        'code_copied': 'Code copied to clipboard',
        'no_files_selected': 'Information',
        'no_files_selected_msg': 'No files selected.',
        'could_not_delete': 'Could not delete {}: {}',
        'files_deleted': 'Success',
        'files_deleted_msg': 'Files deleted successfully.',
        'files_deleted_count': 'Success',
        'files_deleted_count_msg': '{} files were deleted from the room.',
        'selection_required': 'Selection Required',
        'selection_required_msg': 'Please select a file to delete.',
        'single_selection': 'Single Selection',
        'single_selection_msg': 'Please select only ONE file to delete.',
        'file_not_exist': 'Error',
        'file_not_exist_msg': 'The file no longer exists.',
        'file_deleted': 'Success',
        'file_deleted_msg': 'The file \'{}\' was deleted successfully.',
        'delete_error': 'Error',
        'delete_error_msg': 'Could not delete the file: {}',
        'cleanup': 'Cleanup',
        'cleanup_msg': 'Temporal mode active: {} local files were deleted.',
        'cleanup_temp': 'Cleanup',
        'cleanup_temp_msg': 'The temporary content of MultiDesk has been deleted.',
        'already_logged': 'Info',
        'already_logged_msg': 'You are already logged in as {}.',
        'welcome': 'Success',
        'welcome_msg': 'Welcome, {}.',
        'auto_upload': 'Auto-Upload',
        'auto_upload_msg': 'File {} uploaded automatically',
        'upload_error': 'Error',
        'upload_error_msg': 'Error uploading file: {}',
        
        # General Messages
        'success': 'Success',
        'confirmation': 'Confirmation',
        'are_you_sure': 'Are you sure?',
        'user_registered': 'User registered successfully',
        'user_exists': 'User already exists',
        'invalid_credentials': 'Invalid credentials',
        'room_created': 'Room created successfully',
        'room_connected': 'Connected to room',
        'file_uploaded': 'File uploaded successfully',
        'file_downloaded': 'File downloaded successfully',
    }
}

def find_free_port(start_port=8000, max_port=65535):
    """
    Busca un puerto libre comenzando desde start_port.
    Retorna el primer puerto libre encontrado.
    """
    for port in range(start_port, max_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                s.listen(1)
                return port
        except OSError:
            continue
    raise RuntimeError(f"No se encontró un puerto libre entre {start_port} y {max_port}")

# Diccionario que mapea cada dígito a su lista de palabras.
WORDS_MAP = {
    '0': ["mam", "mom", "sol", "mar", "casa", "per", "luz", "pan", "pez", "ave", "uno", "dos", "tres", "voz", "ala", "oro", "sal", "nuez", "uva", "tea", "rat", "sol", "gas", "gel", "red", "map", "box", "key", "zen", "bar", "rio", "ojo", "dia", "pie", "lea", "hay", "mas", "mal", "cal", "del", "por", "sin", "con", "tan", "son", "ver", "dar", "ser", "iré", "ire", "hoy", "fin", "mal", "sol", "mar", "voz", "rey", "paz", "cien", "mil", "feo", "bon", "tal", "tan", "aun", "era", "iba", "fui", "fue", "son", "ven", "vas", "haz", "usa", "usa", "voy", "vaq", "tor", "luz", "sol", "ver", "dar", "rio", "ojo", "pie", "pan", "sol", "rey", "voz", "sal", "ave", "mar", "gas", "gel", "fin", "mal", "hay", "mas", "uno", "dos", "tres", "oro", "uva", "pez", "tea", "rat"],
    '1': ["lol", "lel", "air", "sea", "win", "war", "fun", "run", "sit", "bit", "hit", "fit", "let", "get", "put", "cut", "bet", "wet", "set", "met", "pet", "yet", "lot", "not", "got", "rot", "dot", "pot", "cot", "hot", "mot", "bot", "tip", "sip", "lip", "dip", "hip", "zip", "rip", "pip", "nip", "hop", "pop", "cop", "top", "mop", "sop", "lop", "bob", "rob", "job"],
    '2': ["pop", "pep", "ant", "ape", "bee", "bug", "cat", "cow", "dog", "eel", "emu", "fox", "hen", "hog", "jay", "kit", "owl", "pig", "ram", "rat", "yak", "bat", "cod", "eel", "ape", "owl", "elk", "hen", "ray", "bee", "hog", "cow", "fox", "dog", "cat", "bat", "rat", "pig", "ape", "eel", "jay", "ram", "yak", "owl", "emu", "hen", "cod", "bug", "fox", "cow", "dog"],
    '3': ["kek", "kak", "aba", "abe", "abi", "abo", "abu", "aca", "ace", "aco", "acu", "ada", "ade", "adi", "ado", "adu", "afa", "afe", "afi", "afo", "afu", "aga", "age", "agi", "ago", "agu", "aha", "ahi", "aho", "ahu", "aja", "aje", "ajo", "aju", "aka", "ake", "aki", "ako", "aku", "ala", "ale", "ali", "alo", "alu", "ama", "ame", "ami", "amo", "amu", "ana", "ane", "ani"],
    '4': ["heh", "hoh", "ano", "anu", "apa", "ape", "api", "apo", "apu", "ara", "are", "ari", "aro", "aru", "asa", "ase", "asi", "aso", "asu", "ata", "ate", "ati", "ato", "atu", "ava", "ave", "avi", "avo", "avu", "awa", "axe", "aye", "azo", "eja", "eje", "ejo", "ela", "ele", "eli", "elo", "ema", "eme", "emi", "emo", "ena", "ene", "eni", "eno", "enu", "era", "ere", "eri"],
    '5': ["rir", "ror", "ero", "eru", "esa", "ese", "esi", "eso", "esu", "eta", "ete", "eti", "eto", "etu", "eva", "eve", "evi", "evo", "ewu", "iba", "ibe", "ibi", "ibo", "ibu", "ica", "ice", "ici", "ico", "icu", "ida", "ide", "idi", "ido", "idu", "ifa", "ife", "ifi", "ifo", "ifu", "iga", "ige", "igi", "igo", "igu", "ija", "ije", "ijo", "iju", "ila", "ile", "ili"],
    '6': ["dad", "ded", "ilo", "ilu", "ima", "ime", "imi", "imo", "imu", "ina", "ine", "ini", "ino", "inu", "ipa", "ipe", "ipi", "ipo", "ipu", "ira", "ire", "iri", "iro", "iru", "isa", "ise", "isi", "iso", "isu", "ita", "ite", "iti", "ito", "itu", "iva", "ive", "ivi", "ivo", "ivu", "iwa", "iye", "iza", "ize", "izi", "izo", "izu", "oba", "obe", "obi", "obo", "obu"],
    '7': ["joj", "jej", "oca", "oce", "oci", "oco", "ocu", "oda", "ode", "odi", "odo", "odu", "ofa", "ofe", "ofi", "ofo", "ofu", "oga", "oge", "ogi", "ogo", "ogu", "oja", "oje", "oji", "ojo", "oju", "oka", "oke", "oki", "oko", "oku", "ola", "ole", "oli", "olo", "olu", "oma", "ome", "omi", "omo", "omu", "ona", "one", "oni", "ono", "onu", "opa", "ope", "opi"],
    '8': ["cac", "cec", "opo", "opu", "ora", "ore", "ori", "oro", "oru", "osa", "ose", "osi", "oso", "osu", "ota", "ote", "oti", "oto", "otu", "ova", "ove", "ovi", "ovo", "ovu", "oya", "oye", "oyi", "oyo", "oyu", "uba", "ube", "ubi", "ubo", "ubu", "uca", "uce", "uci", "uco", "ucu", "uda", "ude", "udi", "udo", "udu", "ufa", "ufe", "ufi", "ufo", "ufu", "uga", "uge"],
    '9': ["qoq", "qaq", "ugi", "ugo", "ugu", "uja", "uje", "uji", "ujo", "uju", "uka", "uke", "uki", "uko", "uku", "ula", "ule", "uli", "ulo", "ulu", "uma", "ume", "umi", "umo", "umu", "una", "une", "uni", "uno", "unu", "upa", "upe", "upi", "upo", "upu", "ura", "ure", "uri", "uro", "uru", "usa", "use", "usi", "uso", "usu", "uta", "ute", "uti", "uto", "utu", "uva", "uve"]
}

def encode_number(number):
    """
    Codifica un número en una secuencia de palabras, seleccionando una palabra
    aleatoria de la lista de cada dígito.
    """
    encoded_words = []
    for digit in str(number):
        word_list = WORDS_MAP.get(digit)
        if word_list:
            encoded_words.append(random.choice(word_list))
        else:
            encoded_words.append('???')
    return " ".join(encoded_words)

def decode_number(encoded_string):
    """
    Decodifica una secuencia de palabras de vuelta a un número, identificando
    la lista de palabras a la que pertenece cada una.
    """
    decoded_digits = []
    words = encoded_string.split()
    for word in words:
        found_digit = None
        for digit, word_list in WORDS_MAP.items():
            if word in word_list:
                found_digit = digit
                break
        if found_digit:
            decoded_digits.append(found_digit)
        else:
            decoded_digits.append('?')
    try:
        return int("".join(decoded_digits))
    except ValueError:
        return None

def encode_ip(ip):
    """
    Convierte una IP (ej: 10.3.40.5) en palabras, cada octeto separado por punto.
    Ejemplo: palabra1 palabra2.palabra3.palabra4 palabra5
    """
    octets = ip.split('.')
    encoded_octets = []
    for octet in octets:
        words = []
        for digit in octet:
            word_list = WORDS_MAP.get(digit)
            if word_list:
                words.append(random.choice(word_list))
            else:
                words.append('???')
        encoded_octets.append(' '.join(words))
    return '.'.join(encoded_octets)

def decode_ip(encoded_string):
    """
    Convierte palabras codificadas con puntos a una IP.
    Ejemplo: palabra1 palabra2.palabra3.palabra4 palabra5 -> 10.3.40.5
    """
    octet_words = encoded_string.strip().split('.')
    ip_octets = []
    for octet in octet_words:
        digits = []
        for word in octet.strip().split():
            found_digit = None
            for digit, word_list in WORDS_MAP.items():
                if word in word_list:
                    found_digit = digit
                    break
            if found_digit:
                digits.append(found_digit)
            else:
                digits.append('?')
        ip_octets.append(''.join(digits))
    ip = '.'.join(ip_octets)
    if any('?' in oct for oct in ip_octets):
        return None
    return ip

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
            
        # Eliminar query strings si los hay
        if '?' in path:
            path = path.split('?')[0]
        
        # Handle root path
        if path == '' or path == '/':
            try:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                html = '<html><body><h1>MultiDesk Server</h1><p>Servidor activo</p></body></html>'
                self.wfile.write(html.encode('utf-8'))
            except Exception as e:
                print(f"[ERROR /] {e}")
            return
            
        # Manejo de peticiones /status (para verificar si el host está activo)
        if path == 'status':
            try:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                host_name = getattr(self.server.app, 'host_username', 'Desconocido') if hasattr(self.server, 'app') else 'Desconocido'
                self.wfile.write(json.dumps({'status': 'online', 'host': host_name}).encode('utf-8'))
            except Exception as e:
                print(f"[ERROR /status] {e}")
                self.send_error(500, str(e))
            return
            
        # -----------------------------------------------------
        # Manejo de peticiones /files_list (para la lista de archivos)
        if path == 'files_list':
            try:
                # 1. Obtenemos el nombre desambiguado (ej: "Juan 1")
                resolved_username = self._get_username_from_headers(self.headers)
                client_ip = self.get_client_ip()
                
                if resolved_username and client_ip:
                    
                    # 2. Almacenamos el nombre desambiguado en el mapa del servidor
                    if client_ip not in self.server.user_map or self.server.user_map.get(client_ip) != resolved_username:
                        self.server.user_map[client_ip] = resolved_username 
                        if hasattr(self.server, 'app') and hasattr(self.server.app, 'update_debug_info'):
                            self.server.app.update_debug_info(f"Cliente '{resolved_username}' ({client_ip}) se ha conectado.")
                    
                    # 3. Devolver el nombre de usuario desambiguado en la respuesta HTTP
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('X-Username-Resolved', urllib.parse.quote(resolved_username)) 
                    self.end_headers()
                    
                    # Prepara la lista de archivos para enviar
                    files_info = []
                    if os.path.exists(MULTIDESK_DIR):
                        for fname in os.listdir(MULTIDESK_DIR):
                            filepath = os.path.join(MULTIDESK_DIR, fname)
                            if os.path.isfile(filepath) and not fname.startswith('.'):
                                uploader = self.server.app.upload_history.get(fname, 'Desconocido') if hasattr(self.server, 'app') else 'Desconocido'
                                files_info.append({
                                    'name': fname,
                                    'size': os.path.getsize(filepath),
                                    'uploader': uploader
                                })

                    response_data = {'files': files_info, 'host_name': HOST_SYSTEM_NAME}
                    self.wfile.write(json.dumps(response_data).encode('utf-8'))
                    return
                else:
                    self.send_error(401, "Falta la autenticación (X-Username o X-Client-Ip).")
                    return
                    
            except Exception as e:
                print(f"[ERROR /files_list] {e}")
                import traceback
                traceback.print_exc()
                self.send_error(500, f"Error al procesar /files_list: {str(e)[:100]}")
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
        self.dialog.title(self.app.get_text('diagnostic_title'))
        self.dialog.geometry("700x450")
        self.dialog.transient(master)
        self.dialog.grab_set()
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_close)

        # Marco de botones de diagnóstico
        button_frame = tk.Frame(self.dialog)
        button_frame.pack(pady=5, padx=10, fill="x")
        
        tk.Button(button_frame, text="🔧 Probar Firewall", command=self.test_firewall, bg='orange').pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="🌐 Verificar Red", command=self.test_network, bg='lightblue').pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="🖥️ Probar Conexión", command=self.test_connection, bg='lightgreen').pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="📋 Copiar Todo", command=self.copy_all_logs, bg='lightyellow').pack(side=tk.LEFT, padx=5)

        # Contenedor para la lista de mensajes
        frame = tk.Frame(self.dialog)
        frame.pack(pady=10, padx=10, expand=True, fill="both")

        # Configuración del Listbox y Scrollbar
        scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
        self.info_listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set, width=90, height=18)
        scrollbar.config(command=self.info_listbox.yview)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.info_listbox.pack(side=tk.LEFT, fill="both", expand=True)

        self.add_system_info()

    def add_system_info(self):
        """Añade información de sistema al inicio del panel."""
        self.update_info(self.app.get_text('diagnostic_start'))
        self.update_info(f"{self.app.get_text('operating_system')} {sys.platform} ({os.name})")
        self.update_info(f"{self.app.get_text('hostname')}: {HOST_SYSTEM_NAME}")
        self.update_info(f"{self.app.get_text('reported_ip')}: {self.app.local_ip}")
        self.update_info(f"{self.app.get_text('multidesk_dir')}: {MULTIDESK_DIR}")
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

    def test_firewall(self):
        """Prueba si el firewall está bloqueando conexiones."""
        self.update_info("")
        self.update_info("═══════════════════════════════════════════════════════")
        self.update_info("🔧 PRUEBA DE FIREWALL - Intenta conectar a internet")
        self.update_info("═══════════════════════════════════════════════════════")
        
        try:
            # Intenta conectar a un servidor público conocido (Google DNS)
            response = requests.get('https://www.google.com', timeout=3)
            self.update_info("✓ FIREWALL: Conexión a internet PERMITIDA")
            self.update_info("  Google respondió correctamente")
        except requests.exceptions.Timeout:
            self.update_info("⚠️  FIREWALL: Respuesta lenta de Internet", is_error=True)
        except requests.exceptions.ConnectionError:
            self.update_info("✗ FIREWALL: NO hay conexión a internet", is_error=True)
            self.update_info("  El Firewall podría estar bloqueando salidas", is_error=True)
        except Exception as e:
            self.update_info(f"❓ ERROR inesperado: {str(e)[:50]}", is_error=True)
        
        self.update_info("")

    def test_network(self):
        """Verifica la configuración de red local."""
        self.update_info("")
        self.update_info("═══════════════════════════════════════════════════════")
        self.update_info("🌐 VERIFICACIÓN DE RED LOCAL")
        self.update_info("═══════════════════════════════════════════════════════")
        
        # Información de red
        self.update_info(f"IP Local: {self.app.local_ip}")
        self.update_info(f"Puerto Local: {self.app.port}")
        self.update_info(f"Sistema: {socket.gethostname()}")
        
        if self.app.is_host:
            self.update_info("📡 Modo: HOST (Servidor)")
            self.update_info(f"   Escuchando en: {self.app.local_ip}:{self.app.port}")
        else:
            self.update_info("📱 Modo: CLIENTE")
            if self.app.host_ip:
                self.update_info(f"   Intentando conectar a: {self.app.host_ip}:{self.app.port}")
        
        # Obtén todas las interfaces de red
        try:
            import socket as sock
            hostname = sock.gethostname()
            local_ip = sock.gethostbyname(hostname)
            self.update_info("")
            self.update_info("🖥️  Interfaces de Red Detectadas:")
            
            # Obtener todas las direcciones IP
            for interface_info in socket.getaddrinfo(hostname, None):
                if interface_info[0] == socket.AF_INET:  # IPv4
                    ip = interface_info[4][0]
                    if not ip.startswith('127.'):  # Excluir localhost
                        self.update_info(f"   └─ {ip}")
        except Exception as e:
            self.update_info(f"Error obteniendo interfaces: {str(e)[:50]}", is_error=True)
        
        self.update_info("")

    def test_connection(self):
        """Prueba la conexión al servidor."""
        self.update_info("")
        self.update_info("═══════════════════════════════════════════════════════")
        self.update_info("🖥️  PRUEBA DE CONEXIÓN")
        self.update_info("═══════════════════════════════════════════════════════")
        
        if self.app.is_host:
            self.update_info("✓ Eres el HOST - Estás hosteando la sala")
            self.update_info(f"  Puerto en uso: {self.app.port}")
            self.update_info("  Prueba conectándote desde otra PC con tu código")
        elif not self.app.host_ip:
            self.update_info("⚠️  No hay conexión activa", is_error=True)
            self.update_info("  Primero debes conectarte a una sala", is_error=True)
        else:
            self.update_info(f"Probando conexión a {self.app.host_ip}:{self.app.port}...")
            
            try:
                r = self.app.session.get(f'http://{self.app.host_ip}:{self.app.port}/', timeout=3)
                self.update_info("✓ CONEXIÓN EXITOSA")
                self.update_info(f"  Status HTTP: {r.status_code}")
            except requests.exceptions.ConnectionError:
                self.update_info("✗ ERROR: No se puede alcanzar el servidor", is_error=True)
                self.update_info("  Causas posibles:", is_error=True)
                self.update_info("    1. El HOST no está hosteando la sala", is_error=True)
                self.update_info("    2. Firewall bloqueando el puerto", is_error=True)
                self.update_info("    3. Las PCs no están en la misma RED", is_error=True)
                self.update_info("    4. IP o PUERTO incorrectos", is_error=True)
            except requests.exceptions.Timeout:
                self.update_info("✗ TIMEOUT: El servidor no responde", is_error=True)
                self.update_info("  Verifica que el HOST siga activo", is_error=True)
            except Exception as e:
                self.update_info(f"✗ ERROR: {str(e)[:80]}", is_error=True)
        
        self.update_info("")

    def copy_all_logs(self):
        """Copia todos los logs al portapapeles."""
        try:
            logs = "\n".join(self.info_listbox.get(0, tk.END))
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(logs)
            self.dialog.update()
            messagebox.showinfo("Éxito", "Todos los logs han sido copiados al portapapeles")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo copiar: {str(e)}")

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

        # --- Código de palabras de la IP ---
        code = encode_ip(self.app.local_ip)
        code_with_port = f"{code}:{self.app.port}"
        code_frame = tk.Frame(self.dialog)
        code_frame.pack(pady=5)
        tk.Label(code_frame, text=self.app.get_text('code_for_connection'), font=('Arial', 10, 'bold')).pack()
        code_label = tk.Label(code_frame, text=code_with_port, font=('Arial', 12, 'bold'), fg='darkgreen')
        code_label.pack()

        def copy_code():
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(code_with_port)
            self.dialog.update()
            messagebox.showinfo(self.app.get_text('copied'), self.app.get_text('code_copied'))

        tk.Button(code_frame, text=self.app.get_text('copy_code'), command=copy_code).pack(pady=2)

        self.notebook = ttk.Notebook(self.dialog)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        self.tab_users = tk.Frame(self.notebook)
        self.notebook.add(self.tab_users, text=self.app.get_text('connected_users'))
        self._setup_users_tab()

        self.tab_files = tk.Frame(self.notebook)
        self.notebook.add(self.tab_files, text=self.app.get_text('file_management'))
        self._setup_files_tab()

        tk.Button(self.dialog, text=self.app.get_text('close_room'), fg="red", command=self.close_room).pack(pady=10)

        self.update_users_list()


    def _setup_users_tab(self):
        tk.Label(self.tab_users, text=self.app.get_text('active_users'), font=('Arial', 10)).pack(pady=5)
        
        self.users_listbox = tk.Listbox(self.tab_users, width=50, height=15)
        self.users_listbox.pack(pady=10, padx=10)

    def _setup_files_tab(self):
        tk.Label(self.tab_files, text=self.app.get_text('files_in_multidesk'), font=('Arial', 10)).pack(pady=5)
        
        self.file_listbox_control = tk.Listbox(self.tab_files, selectmode=tk.MULTIPLE, width=70, height=15)
        self.file_listbox_control.pack(pady=5, padx=10)
        self.update_file_list_control()

        btn_frame = tk.Frame(self.tab_files)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text=self.app.get_text('delete_selected'), fg="orange", command=self.delete_selected_files).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text=self.app.get_text('delete_all_files'), fg="red", command=self.delete_all_files).pack(side=tk.LEFT, padx=5)
        # 🆕 Botón para borrar un solo archivo seleccionado
        tk.Button(btn_frame, text=self.app.get_text('delete_file'), fg="red", command=self.delete_single_file).pack(side=tk.LEFT, padx=5)


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
            messagebox.showinfo(self.app.get_text('no_files_selected'), self.app.get_text('no_files_selected_msg'))
            return

        confirm = messagebox.askyesno(self.app.get_text('confirmation'), f"¿Estás seguro de que quieres eliminar {len(selected_indices)} archivo(s) seleccionado(s)?")
        if confirm:
            for index in selected_indices:
                filename = self.file_listbox_control.get(index)
                filepath = os.path.join(MULTIDESK_DIR, filename)
                try:
                    os.remove(filepath)
                    if filename in self.app.upload_history:
                        del self.app.upload_history[filename]
                except Exception as e:
                    messagebox.showerror(self.app.get_text('error'), self.app.get_text('could_not_delete').format(filename, e))

            self.app.save_upload_history()
            self.update_file_list_control()
            self.app.update_files()
            messagebox.showinfo(self.app.get_text('files_deleted'), self.app.get_text('files_deleted_msg'))

    def delete_all_files(self):
        confirm = messagebox.askyesno(self.app.get_text('confirmation'), 
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
            messagebox.showinfo(self.app.get_text('files_deleted_count'), self.app.get_text('files_deleted_count_msg').format(files_deleted))

    def delete_single_file(self):
        """Elimina un único archivo seleccionado en la lista de gestión de archivos."""
        try:
            selection = self.file_listbox_control.curselection()
            if not selection:
                messagebox.showwarning(self.app.get_text('selection_required'), self.app.get_text('selection_required_msg'))
                return
            
            if len(selection) > 1:
                messagebox.showwarning(self.app.get_text('single_selection'), self.app.get_text('single_selection_msg'))
                return
            
            # Obtener el nombre del archivo seleccionado
            filename = self.file_listbox_control.get(selection[0])
            
            # Confirmar la eliminación
            if not messagebox.askyesno(self.app.get_text('confirmation'), 
                                     f"¿Estás seguro de que quieres eliminar el archivo '{filename}'?"):
                return
            
            filepath = os.path.join(MULTIDESK_DIR, filename)
            
            # Verificar que el archivo existe
            if not os.path.exists(filepath):
                messagebox.showerror(self.app.get_text('file_not_exist'), self.app.get_text('file_not_exist_msg'))
                self.update_file_list_control()
                return
            
            # Intentar eliminar el archivo
            os.remove(filepath)
            
            # Si se elimina correctamente, actualizar el historial y la interfaz
            if filename in self.app.upload_history:
                del self.app.upload_history[filename]
                self.app.save_upload_history()
            
            self.update_file_list_control()
            messagebox.showinfo(self.app.get_text('file_deleted'), self.app.get_text('file_deleted_msg').format(filename))
            
        except Exception as e:
            messagebox.showerror(self.app.get_text('delete_error'), self.app.get_text('delete_error_msg').format(str(e)))
            self.app.update_debug_info(f"Error en delete_single_file: {str(e)}", is_error=True)

    def close_room(self):
        # El host debe confirmar que desea cerrar la sala
        if messagebox.askyesno(self.app.get_text('confirmation'), "¿Estás seguro de que quieres cerrar la sala y desconectar a todos los usuarios?"):
            if self.app.server:
                # 🆕 Indica que el servidor está cerrado antes del shutdown
                self.app.server.closed = True 
                
                # El shutdown debe ejecutarse en un hilo separado ya que bloquea el hilo principal
                threading.Thread(target=self.app.server.shutdown, daemon=True).start()
                self.app.server = None # Limpiar la referencia
                
            # 🆕 Limpieza si el HOST está en modo temporal
            if self.app.is_temporal_mode.get():
                cleanup_count = cleanup_multidesk(is_host=True)
                messagebox.showinfo(self.app.get_text('cleanup'), self.app.get_text('cleanup_msg').format(cleanup_count))

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
        self.current_language = tk.StringVar(value='es')
        self.files_list = []
        self.host_name = 'Host Desconocido'
        
        # Multi-Square Configuration
        self.multi_square_enabled = tk.BooleanVar(value=False)
        self.multi_square_window = None
        self.multi_square_size = (100, 100)  # Default size (width, height)
        self.multi_square_position = (0, 0)  # Default position (x, y)
        self.window_hover_start = None
        self.hover_timeout = 2000  # 2 seconds in milliseconds
        self.current_hover_window = None
        
        # Load saved configuration
        self.load_config()
        
        self.setup_db()
        self.setup_main_menu()
        self.load_upload_history()
        
        if self.multi_square_enabled.get():
            self.show_multi_square()
            
    def load_config(self):
        """Load configuration from a JSON file"""
        config_file = os.path.join(os.getcwd(), 'multidesk_config.json')
        if not os.path.exists(config_file):
            return

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # Safely set boolean flags and tuples with sensible defaults
            self.is_temporal_mode.set(bool(config.get('temporal_mode', False)))
            self.multi_square_enabled.set(bool(config.get('multi_square_enabled', False)))
            
            # Load language preference
            language = config.get('language', 'es')
            if language in TRANSLATIONS:
                self.current_language.set(language)
            else:
                self.current_language.set('es')

            size = config.get('multi_square_size', [100, 100])
            pos = config.get('multi_square_position', [0, 0])

            try:
                self.multi_square_size = tuple(int(x) for x in size)
            except Exception:
                self.multi_square_size = (100, 100)

            try:
                self.multi_square_position = tuple(int(x) for x in pos)
            except Exception:
                self.multi_square_position = (0, 0)

        except Exception as e:
            print(f"Error loading configuration: {e}")
            try:
                messagebox.showerror("Error", f"Error loading configuration: {e}")
            except Exception:
                # If messagebox fails (e.g., during unit tests), just continue
                pass

    def save_config(self):
        """Save configuration to a JSON file"""
        config = {
            'temporal_mode': self.is_temporal_mode.get(),
            'multi_square_enabled': self.multi_square_enabled.get(),
            'multi_square_size': list(self.multi_square_size),
            'multi_square_position': list(self.multi_square_position),
            'language': self.current_language.get()
        }
        config_file = os.path.join(os.getcwd(), 'multidesk_config.json')
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")

    def get_text(self, key):
        """Get translated text based on current language"""
        lang = self.current_language.get()
        if lang in TRANSLATIONS and key in TRANSLATIONS[lang]:
            return TRANSLATIONS[lang][key]
        # Fallback to Spanish
        if key in TRANSLATIONS['es']:
            return TRANSLATIONS['es'][key]
        return key

    def show_config_dialog(self):
        """Show configuration dialog"""
        dialog = Toplevel(self.root)
        dialog.title(self.get_text('config_title'))
        dialog.geometry("400x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Language Selection
        lang_frame = tk.LabelFrame(dialog, text=self.get_text('language'), padx=10, pady=5)
        lang_frame.pack(fill="x", padx=10, pady=5)
        
        lang_var = tk.StringVar(value=self.current_language.get())
        tk.Radiobutton(lang_frame, text="Español", variable=lang_var, value='es').pack(anchor="w")
        tk.Radiobutton(lang_frame, text="English", variable=lang_var, value='en').pack(anchor="w")

        # Temporal Mode
        temp_frame = tk.LabelFrame(dialog, text=self.get_text('temporal_mode'), padx=10, pady=5)
        temp_frame.pack(fill="x", padx=10, pady=5)
        tk.Checkbutton(temp_frame, text=self.get_text('enable_temporal'), variable=self.is_temporal_mode).pack()
        tk.Label(temp_frame, text=self.get_text('temporal_desc'), font=('Arial', 8)).pack()

        # Multi-Square Configuration
        ms_frame = tk.LabelFrame(dialog, text=self.get_text('multi_square'), padx=10, pady=5)
        ms_frame.pack(fill="x", padx=10, pady=5)

        # Enable/Disable Multi-Square
        tk.Checkbutton(ms_frame, text=self.get_text('enable_multi_square'), variable=self.multi_square_enabled,
                      command=self.toggle_multi_square).pack()

        # Size Configuration
        size_frame = tk.Frame(ms_frame)
        size_frame.pack(fill="x", pady=5)
        tk.Label(size_frame, text=self.get_text('size')).pack(side="left")
        
        width_var = tk.StringVar(value=str(self.multi_square_size[0]))
        height_var = tk.StringVar(value=str(self.multi_square_size[1]))
        
        tk.Entry(size_frame, textvariable=width_var, width=5).pack(side="left", padx=5)
        tk.Label(size_frame, text="x").pack(side="left")
        tk.Entry(size_frame, textvariable=height_var, width=5).pack(side="left", padx=5)

        # Position Configuration
        pos_frame = tk.Frame(ms_frame)
        pos_frame.pack(fill="x", pady=5)
        tk.Label(pos_frame, text=self.get_text('position')).pack(side="left")
        
        x_var = tk.StringVar(value=str(self.multi_square_position[0]))
        y_var = tk.StringVar(value=str(self.multi_square_position[1]))
        
        tk.Entry(pos_frame, textvariable=x_var, width=5).pack(side="left", padx=5)
        tk.Label(pos_frame, text=",").pack(side="left")
        tk.Entry(pos_frame, textvariable=y_var, width=5).pack(side="left", padx=5)

        def save_and_close():
            # Check if language changed
            language_changed = lang_var.get() != self.current_language.get()
            
            # Update language
            self.current_language.set(lang_var.get())
            
            # Update Multi-Square size and position
            try:
                self.multi_square_size = (int(width_var.get()), int(height_var.get()))
                self.multi_square_position = (int(x_var.get()), int(y_var.get()))
            except ValueError:
                messagebox.showerror(self.get_text('error'), self.get_text('integer_error'))
                return

            self.save_config()
            
            # Update Multi-Square if it's enabled
            if self.multi_square_enabled.get():
                if self.multi_square_window:
                    self.multi_square_window.destroy()
                self.show_multi_square()
            
            dialog.destroy()
            
            # If language changed and in a room, reload the interface
            if language_changed:
                if self.is_host or self.host_ip:
                    # Reload room window to apply translations
                    self.root.after(100, self.show_room_window)

        # Save Button
        tk.Button(dialog, text=self.get_text('save'), command=save_and_close).pack(pady=10)

    def toggle_multi_square(self):
        """Toggle Multi-Square visibility"""
        if self.multi_square_enabled.get():
            self.show_multi_square()
        else:
            if self.multi_square_window:
                self.multi_square_window.destroy()
                self.multi_square_window = None

    def show_multi_square(self):
        """Show Multi-Square window"""
        if self.multi_square_window:
            self.multi_square_window.destroy()

        self.multi_square_window = Toplevel(self.root)
        self.multi_square_window.title("Multi-Square")
        self.multi_square_window.overrideredirect(True)  # Remove window decorations
        self.multi_square_window.attributes('-topmost', True)  # Keep window on top
        
        # Set window size and position
        self.multi_square_window.geometry(f"{self.multi_square_size[0]}x{self.multi_square_size[1]}+{self.multi_square_position[0]}+{self.multi_square_position[1]}")

        # Create canvas for visual feedback
        canvas = tk.Canvas(self.multi_square_window, bg='lightblue', highlightthickness=2)
        canvas.pack(fill="both", expand=True)

        # Make window draggable
        canvas.bind('<Button-1>', self.start_drag)
        canvas.bind('<B1-Motion>', self.on_drag)

        # Mouse hover detection
        canvas.bind('<Enter>', self.on_hover_start)
        canvas.bind('<Leave>', self.on_hover_end)

        # Bind right-click to show context menu
        canvas.bind('<Button-3>', self.show_square_menu)

        # Helpful instruction text
        try:
            canvas.create_text(self.multi_square_size[0] // 2, self.multi_square_size[1] // 2,
                               text="Arrastra archivos aquí\n(o haz doble clic)",
                               font=('Arial', 10), fill='black', justify='center')
        except Exception:
            pass

        # Double-click opens a file dialog as a fallback to add files
        canvas.bind('<Double-Button-1>', lambda e: self.select_file())

        # Register drag & drop handlers (optional backends)
        # Try tkinterdnd2 first, but if it fails, fall back to windnd
        dnd_registered = False
        
        if TKDND_AVAILABLE:
            try:
                # tkinterdnd2: register the canvas as drop target
                canvas.drop_target_register(DND_FILES)
                canvas.dnd_bind('<<Drop>>', lambda e: self._handle_drop_event(e.data))
                print("[INFO] tkinterdnd2 DnD registered successfully")
                dnd_registered = True
            except Exception as ex:
                # Common cause: tkinterdnd2 Python package is present but the underlying
                # tkdnd Tcl/Tk extension is not installed or not found by Tk.
                print(f"[WARN] tkinterdnd2 binding failed: {ex}")
                print("[INFO] Falling back to windnd...")
                # Fall through to windnd attempt below
        
        # If tkinterdnd2 didn't work, try windnd
        if not dnd_registered and WINDND_AVAILABLE:
            try:
                # windnd: hook the toplevel window. windnd passes a list of byte paths.
                def _windnd_callback(files, *args):
                    """Callback for windnd drop events."""
                    try:
                        paths = [f.decode('utf-8') if isinstance(f, bytes) else str(f) for f in files]
                    except Exception:
                        paths = [str(f) for f in files]
                    print(f"[DEBUG windnd] Received {len(paths)} file(s): {paths}")
                    self._process_dropped_paths(paths)

                print(f"[DEBUG windnd] Hooking dropfiles on window: {self.multi_square_window}")
                windnd.hook_dropfiles(self.multi_square_window, _windnd_callback)
                self.update_debug_info("✓ windnd DnD activado correctamente en Multi-Square.")
                print("[INFO] windnd DnD registered successfully")
                dnd_registered = True
            except Exception as ex:
                import traceback
                tb = traceback.format_exc()
                self.update_debug_info(
                    f"windnd falló al hookear dropfiles:\n{ex}\n\nDetalles:\n{tb}",
                    is_error=True
                )
                print(f"[ERROR windnd] {tb}")
        
        # Show appropriate message if no DnD backend worked
        if not dnd_registered:
            if TKDND_AVAILABLE:
                # tkinterdnd2 was available but failed
                self.update_debug_info(
                    "Error al activar tkinterdnd2: falta la extensión tkdnd en tu instalación de Tcl/Tk.\n"
                    + "Solución: Instala 'windnd' (pip install windnd) y reinicia.\n"
                    + "Usando fallback: doble-clic en Multi-Square para seleccionar archivos.",
                    is_error=True
                )
            elif WINDND_AVAILABLE:
                # This shouldn't happen if windnd is available, but just in case
                self.update_debug_info("windnd está disponible pero falló. Usando fallback: doble-clic.", is_error=True)
            else:
                # No DnD backend available at all
                self.update_debug_info(
                    "Drag & Drop no disponible.\n"
                    + "Para habilitar DnD: pip install windnd (Windows) o pip install tkinterdnd2 (multiplataforma)\n"
                    + "Usando fallback: doble-clic en Multi-Square.",
                    is_error=True
                )

    def start_drag(self, event):
        """Start dragging the Multi-Square"""
        self.multi_square_window._drag_start_x = event.x_root - self.multi_square_window.winfo_x()
        self.multi_square_window._drag_start_y = event.y_root - self.multi_square_window.winfo_y()

    def on_drag(self, event):
        """Handle Multi-Square dragging"""
        x = event.x_root - self.multi_square_window._drag_start_x
        y = event.y_root - self.multi_square_window._drag_start_y
        self.multi_square_window.geometry(f"+{x}+{y}")
        self.multi_square_position = (x, y)
        self.save_config()

    def show_square_menu(self, event):
        """Show context menu for Multi-Square"""
        menu = tk.Menu(self.multi_square_window, tearoff=0)
        menu.add_command(label="Cerrar", command=self.close_multi_square)
        menu.add_separator()
        menu.add_command(label="Configurar", command=self.show_config_dialog)
        menu.post(event.x_root, event.y_root)

    def close_multi_square(self):
        """Close Multi-Square window"""
        self.multi_square_enabled.set(False)
        if self.multi_square_window:
            self.multi_square_window.destroy()
            self.multi_square_window = None
        self.save_config()

    def on_hover_start(self, event):
        """Handle when a window starts hovering over Multi-Square"""
        if not self.is_host:  # Only work when we're the host
            return
            
        self.window_hover_start = time.time()
        self.root.after(100, self.check_hover)  # Check every 100ms

    def on_hover_end(self, event):
        """Handle when a window stops hovering over Multi-Square"""
        self.window_hover_start = None
        self.current_hover_window = None

    def check_hover(self):
        """Check if a window has been hovering long enough"""
        if not self.window_hover_start:
            # Evita spamear la salida/console cuando el panel de debug no está abierto.
            if self.debug_panel_instance:
                self.update_debug_info("No hay hover activo")
            return
            
        if not self.multi_square_window:
            if self.debug_panel_instance:
                self.update_debug_info("Ventana Multi-Square no está activa")
            return
            
        # Get current mouse position
        x = self.multi_square_window.winfo_pointerx()
        y = self.multi_square_window.winfo_pointery()
        
        # Get the window under the cursor
        window_under_cursor = self.multi_square_window.winfo_containing(x, y)
        
        if window_under_cursor and window_under_cursor != self.multi_square_window:
            current_time = time.time()
            hover_duration = (current_time - self.window_hover_start) * 1000  # Convert to milliseconds
            
            if hover_duration >= self.hover_timeout:
                # If we have a new window
                if window_under_cursor != self.current_hover_window:
                    self.current_hover_window = window_under_cursor
                    # Try to get the file path associated with the window
                    try:
                        window_title = window_under_cursor.winfo_toplevel().title()
                        # If it's a file window, it might contain the file path
                        if os.path.exists(window_title):
                            self.share_file(window_title)
                    except:
                        pass  # If we can't get the window title or it's not a valid file
            
            # Continue checking
            self.root.after(100, self.check_hover)

        hover_time = (time.time() - self.window_hover_start) * 1000  # Convert to milliseconds
        
        if hover_time >= self.hover_timeout:
            self.window_hover_start = None  # Reset the timer
            self.trigger_auto_upload()
        else:
            self.root.after(100, self.check_hover)  # Keep checking

    def trigger_auto_upload(self):
        """Trigger automatic file upload for the hovered window"""
        if not self.is_host or not self.selected_file_name:
            return
            
        try:
            filepath = os.path.join(MULTIDESK_DIR, self.selected_file_name)
            if os.path.exists(filepath):
                # Proceed with file upload
                self.register_upload(self.selected_file_name, self.current_user)
                messagebox.showinfo(self.get_text('auto_upload'), self.get_text('auto_upload_msg').format(self.selected_file_name))
        except Exception as e:
            messagebox.showerror(self.get_text('error'), self.get_text('upload_error_msg').format(str(e)))
            self.update_debug_info(f"Error en auto-upload: {str(e)}", is_error=True)
        
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
            self.ip_display_label.config(text=f"{self.get_text('local_ip')} {self.local_ip}", fg='darkgreen')

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
            messagebox.showinfo(self.get_text('cleanup_temp'), self.get_text('cleanup_temp_msg'))
            
        # 🆕 Restablece el estado de host
        self.is_host = False 
        
        for widget in self.root.winfo_children():
            widget.destroy()
            
        tk.Label(self.root, text=self.get_text('title'), font=('Arial', 18)).pack(pady=10)
        
        # Crear un frame para los botones principales
        main_buttons_frame = tk.Frame(self.root)
        main_buttons_frame.pack(pady=5)
        
        # Botones principales
        tk.Button(main_buttons_frame, text=self.get_text('host_room'), width=20, command=self.host_room).pack(pady=5)
        tk.Button(main_buttons_frame, text=self.get_text('connect_room'), width=20, command=self.connect_room).pack(pady=5)
        tk.Button(main_buttons_frame, text=self.get_text('register_user'), width=20, command=self.show_register_dialog).pack(pady=5)

        # Botón de configuración
        config_button = tk.Button(main_buttons_frame, text=self.get_text('configuration'), width=20, command=self.show_config_dialog)
        config_button.pack(pady=5)
          
        
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
            messagebox.showinfo(self.get_text('already_logged'), self.get_text('already_logged_msg').format(self.current_user))
            return True
            
        username = simpledialog.askstring('Autenticación', 'Usuario:')
        if not username:
            return False
        password = simpledialog.askstring('Autenticación', 'Contraseña:', show='*')
        if not password:
            return False
        
        success, msg = self.authenticate_user(username, password)

        if success:
            messagebox.showinfo(self.get_text('welcome'), self.get_text('welcome_msg').format(self.current_user))
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
        dialog.title(self.get_text('register_user'))
        # 🆕 Ajusta la geometría para dar espacio al botón de info
        dialog.geometry("350x180")
        dialog.transient(self.root)
        dialog.grab_set()

        # Frame para la contraseña y el botón de info
        pass_frame = tk.Frame(dialog)
        pass_frame.pack(pady=5)

        tk.Label(dialog, text=self.get_text('username')).pack(pady=5)
        user_entry = tk.Entry(dialog)
        user_entry.pack()
        if username: user_entry.insert(0, username)
        
        tk.Label(pass_frame, text=self.get_text('password')).pack(side=tk.LEFT)
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
                messagebox.showinfo(self.get_text('success'), msg)
                dialog.destroy()
            else:
                messagebox.showerror(self.get_text('error'), msg)

        tk.Button(dialog, text=self.get_text('register'), command=register_action).pack(pady=10)
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
                # Busca un puerto libre comenzando desde self.port
                free_port = find_free_port(self.port)
                self.port = free_port  # Actualiza el puerto de la instancia
                
                handler = lambda *args, **kwargs: CustomHandler(*args, app_instance=self, base_dir=MULTIDESK_DIR, **kwargs)
                
                # Intenta iniciar el servidor en la IP local específica
                # Usar self.local_ip en lugar de 0.0.0.0 asegura que los clientes puedan conectar
                self.server = AuthTCPServer((self.local_ip, self.port), handler, set())
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
        self.show_room_window()
        self.server.user_map[self.local_ip] = self.current_user
        self.open_debug_panel() 
        
        # Mensajes de diagnóstico mejorados
        self.update_debug_info(f'')
        self.update_debug_info(f'╔════════════════════════════════════════════╗')
        self.update_debug_info(f'║        🟢 SALA HOSTEADA EXITOSAMENTE       ║')
        self.update_debug_info(f'╚════════════════════════════════════════════╝')
        self.update_debug_info(f'')
        self.update_debug_info(f'📡 Información del Servidor:')
        self.update_debug_info(f'   IP LOCAL: {self.local_ip}')
        self.update_debug_info(f'   PUERTO: {self.port}')
        self.update_debug_info(f'   HOST: {self.current_user}')
        self.update_debug_info(f'')
        self.update_debug_info(f'📋 Para conectar (copia el código o la IP):')
        self.update_debug_info(f'   Código de palabras: (ver arriba en la sala)')
        self.update_debug_info(f'   O dirección directa: {self.local_ip}:{self.port}')
        self.update_debug_info(f'')
        self.update_debug_info(f'⚠️  IMPORTANTE - Firewall:')
        self.update_debug_info(f'   Si los clientes NO pueden conectarse:')
        self.update_debug_info(f'   1. Abre el Firewall de Windows')
        self.update_debug_info(f'   2. Permite Python.exe o MultiDesk.exe')
        self.update_debug_info(f'   3. Abre el puerto {self.port} en el Firewall')
        self.update_debug_info(f'   4. Verifica que ambas PCs estén en la MISMA RED')
        self.update_debug_info(f'')
        
        # Re-show multi-square if it's enabled
        if self.multi_square_enabled.get():
            self.show_multi_square()
        
    def _handle_server_startup_error(self):
        """Maneja el error devuelto por el hilo del servidor en el hilo principal."""
        error_msg = self.server_error
        self.is_host = False # Resetea el estado host si el inicio falló.
        self.server_error = None # Limpia el error

        # Error inesperado (no debería ocurrir si find_free_port funciona correctamente)
        messagebox.showerror("Error de Host", f"Error inesperado al iniciar el servidor: {error_msg}")
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
        
        # Pide el código de palabras o la IP y Puerto al Cliente
        host_info = simpledialog.askstring('Conectar', 
                                          f'Código de palabras o Dirección del Host (ej. palabra1 palabra2.palabra3 palabra4:8000 o 192.168.1.10:8000):',
                                          initialvalue=f'{self.local_ip}:{self.port}')
        if not host_info:
            return
        
        try:
            host_info = host_info.strip()
            decoded_ip = None
            port_from_code = None
            
            # Intenta decodificar como código de palabras
            if ':' in host_info:
                # Separa la parte del código y el puerto
                code_part, port_str = host_info.rsplit(':', 1)
                try:
                    port_from_code = int(port_str.strip())
                    # Intenta decodificar el código de palabras
                    decoded_ip = decode_ip(code_part.strip())
                except (ValueError, IndexError):
                    pass
            else:
                # Intenta decodificar sin puerto (usa el puerto por defecto)
                decoded_ip = decode_ip(host_info)
            
            # Si se decodificó exitosamente un código de palabras
            if decoded_ip:
                self.host_ip = decoded_ip
                if port_from_code:
                    self.port = port_from_code
                messagebox.showinfo('Éxito', f'Código decodificado exitosamente.\nIP: {self.host_ip}\nPuerto: {self.port}')
            else:
                # Si no es un código de palabras, intenta interpretarlo como IP:PUERTO
                if ':' in host_info:
                    ip_parts = host_info.split(':')
                    self.host_ip = ip_parts[0].strip()
                    self.port = int(ip_parts[1].strip())
                else:
                    self.host_ip = host_info.strip()
            
            if not self.host_ip:
                 messagebox.showerror('Error', 'Debe ingresar una dirección IP válida o un código de palabras válido.')
                 return
                 
        except (ValueError, IndexError):
            messagebox.showerror('Error', 'Formato incorrecto. Use:\n- Código de palabras: palabra1 palabra2.palabra3:PUERTO\n- IP:PUERTO o solo IP.')
            return


        self.is_host = False

        if self.connect_to_server(self.host_ip):
            self.show_room_window()
            self.open_debug_panel()
            self.update_debug_info(f'[✓ SALA ACTIVA] Conectado a {self.host_ip} en puerto {self.port}')
            
            self.client_updater_running = True
            threading.Thread(target=self.fetch_and_update_client_files, daemon=True).start()
        else:
            # Mensaje de error mejorado con soluciones
            error_msg = (
                f'❌ NO SE PUDO CONECTAR A LA SALA\n\n'
                f'Dirección: {self.host_ip}:{self.port}\n\n'
                f'Causas posibles:\n'
                f'  1. El HOST no está hosteando la sala (debe estar ejecutando)\n'
                f'  2. El PUERTO es incorrecto (verifica el código de palabras)\n'
                f'  3. FIREWALL bloqueando el puerto {self.port}\n'
                f'  4. Las computadoras NO están en la misma RED\n'
                f'  5. IP del servidor incorrecta\n\n'
                f'Soluciones:\n'
                f'  • Asegúrate que el HOST tenga abierta la sala\n'
                f'  • Usa el código de palabras completo (con puerto)\n'
                f'  • Desactiva/permite el puerto en el Firewall\n'
                f'  • Verifica que ambas estén en la misma red (LAN)\n'
                f'  • Abre el panel de Diagnóstico para más detalles'
            )
            messagebox.showerror('Error de Conexión', error_msg)
            self.open_debug_panel()  # Abre automáticamente el panel de diagnóstico
             
    def connect_to_server(self, ip):
        """Intenta realizar una petición GET para verificar si el servidor está activo."""
        self.update_debug_info(f'[CONEXIÓN] Verificando disponibilidad del servidor...')
        
        # Intentar múltiples veces con esperas
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                self.update_debug_info(f'[INTENTO {attempt}/{max_attempts}] Conectando a {ip}:{self.port}...')
                
                r = self.session.get(f'http://{ip}:{self.port}/', timeout=5)
                r.raise_for_status()
                
                # Conexión exitosa
                self.update_debug_info(f'[✓ CONEXIÓN EXITOSA] Conectado a {ip}:{self.port}', is_error=False)
                return True
                
            except requests.exceptions.ConnectionError as e:
                self.update_debug_info(f'[INTENTO {attempt}] Error de conexión: {str(e)[:80]}', is_error=True)
                if attempt < max_attempts:
                    self.update_debug_info(f'[INTENTO {attempt}] Reintentando en 1 segundo...')
                    time.sleep(1)
                    
            except requests.exceptions.Timeout as e:
                self.update_debug_info(f'[INTENTO {attempt}] Timeout: El servidor no responde', is_error=True)
                if attempt < max_attempts:
                    self.update_debug_info(f'[INTENTO {attempt}] Reintentando en 1 segundo...')
                    time.sleep(1)
                    
            except requests.exceptions.RequestException as e:
                self.update_debug_info(f'[INTENTO {attempt}] Error HTTP: {str(e)[:80]}', is_error=True)
                if attempt < max_attempts:
                    self.update_debug_info(f'[INTENTO {attempt}] Reintentando en 1 segundo...')
                    time.sleep(1)
        
        # Después de todos los intentos fallidos
        self.update_debug_info(f'[✗ CONEXIÓN FALLIDA] No se puede conectar a {ip}:{self.port}', is_error=True)
        self.update_debug_info(f'Posibles causas:', is_error=True)
        self.update_debug_info(f'  1. El HOST no está hosteando la sala', is_error=True)
        self.update_debug_info(f'  2. Firewall bloqueando el puerto {self.port}', is_error=True)
        self.update_debug_info(f'  3. Las computadoras NO están en la misma RED', is_error=True)
        self.update_debug_info(f'  4. IP o PUERTO incorrectos', is_error=True)
        return False

    def show_room_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10, padx=10, fill='x')
        
        self.room_title_var = tk.StringVar(self.root)
        
        # Simple room title for both host and client
        self.room_title_var.set('SALA:')

        tk.Label(top_frame, textvariable=self.room_title_var, font=('Arial', 16)).pack(side=tk.LEFT)
        
        if self.is_host:
            tk.Button(top_frame, text=self.get_text('control_panel'), command=self.open_control_panel, bg='lightblue').pack(side=tk.RIGHT)
        
        # Botones de control
        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=5)
        
        tk.Button(control_frame, text=self.get_text('select_file_upload'), command=self.select_file).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text=self.get_text('diagnostics'), command=self.open_debug_panel, bg='lightgray').pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text=self.get_text('leave'), command=self.leave_room).pack(side=tk.LEFT, padx=5)
        
        # 🆕 Botones de gestión de archivos (Cliente/Descarga)
        file_action_frame = tk.Frame(self.root)
        file_action_frame.pack(pady=5)
        tk.Button(file_action_frame, text=self.get_text('download_selected'), command=self.download_selected_file, bg='lightgreen').pack(side=tk.LEFT, padx=5)
        if not self.is_host:
            tk.Button(file_action_frame, text=self.get_text('delete_my_upload'), command=self.client_delete_file, fg='red').pack(side=tk.LEFT, padx=5)
        
        # Etiqueta de la lista de archivos
        tk.Label(self.root, text=self.get_text('shared_files'), font=('Arial', 10, 'bold')).pack(pady=(10, 0))

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
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while self.client_updater_running:
            if not self.host_ip:
                self.client_updater_running = False
                break
                
            try:
                # Usamos el nombre actual (puede ser el original o ya desambiguado)
                headers = {'X-Username': self.current_user, 'X-Client-Ip': self.local_ip}
                self.update_debug_info(f"[CLIENTE] Solicitando lista de archivos a {self.host_ip}:{self.port}...")
                response = self.session.get(f'http://{self.host_ip}:{self.port}/files_list', headers=headers, timeout=5)
                
                if response.status_code == 200:
                    consecutive_errors = 0  # Resetear contador de errores
                    
                    # 🆕 Recuperar el nombre de usuario desambiguado del Host
                    resolved_username_encoded = response.headers.get('X-Username-Resolved')
                    if resolved_username_encoded:
                        # Si el Host nos dio un nombre único (ej: Juan 1), lo usamos
                        new_current_user = urllib.parse.unquote(resolved_username_encoded)
                        if new_current_user != self.current_user:
                             self.update_debug_info(f"✓ Nombre actualizado por el Host a: {new_current_user}")
                             self.current_user = new_current_user
                    
                    try:
                        data = response.json()
                        new_files = data.get('files', [])
                        self.host_name = data.get('host_name', 'Host Desconocido')
                        self.update_debug_info(f"[CLIENTE] Recibidos {len(new_files)} archivo(s) del Host")
                        
                        # Comprueba si la lista ha cambiado (optimizando la actualización de la UI)
                        if new_files != self.files_list:
                            self.files_list = new_files
                            self.root.after(0, self._update_client_files_ui)
                    except json.JSONDecodeError as e:
                        self.update_debug_info(f"[ERROR CLIENTE] No se pudo parsear JSON del Host: {e}", is_error=True)
                        
                elif response.status_code == 401:
                    self.client_updater_running = False
                    self.update_debug_info(f"[ERROR CLIENTE] Autenticación rechazada (401)", is_error=True)
                    self.root.after(0, lambda: messagebox.showerror("Conexión Fallida", "No se pudo autenticar con el Host. Verifique sus credenciales."))
                    self.root.after(0, self.setup_main_menu)
                    break
                    
                else:
                    # Esto incluye 404, 500, etc.
                    self.update_debug_info(f"[ERROR CLIENTE] Host respondió con status {response.status_code}: {response.text[:100]}", is_error=True)
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        self.client_updater_running = False
                        self.root.after(0, lambda: messagebox.showerror("Conexión Perdida", f"El Host ha dejado de responder después de {consecutive_errors} intentos."))
                        self.root.after(0, self.setup_main_menu)
                        break
                    
            except requests.exceptions.RequestException as e:
                consecutive_errors += 1
                self.update_debug_info(f"[ERROR CLIENTE] Fallo de conexión (intento {consecutive_errors}/{max_consecutive_errors}): {str(e)[:80]}", is_error=True)
                if consecutive_errors >= max_consecutive_errors:
                    self.client_updater_running = False
                    self.root.after(0, lambda: messagebox.showerror("Conexión Terminada", f"El Host ha cerrado la conexión o no responde."))
                    self.root.after(0, self.setup_main_menu)
                    break
                    
            except Exception as e:
                self.update_debug_info(f"[ERROR INESPERADO CLIENTE] {e}", is_error=True)
                import traceback
                traceback.print_exc()
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    self.client_updater_running = False
                    break

            time.sleep(FILE_UPDATE_INTERVAL / 1000)
    
    def _update_client_files_ui(self):
        """Actualiza la interfaz de usuario de la lista de archivos del cliente."""
        if self.files_listbox:
            self.files_listbox.delete(0, tk.END)
            for file_info in self.files_list:
                filename = file_info.get('name', '')
                uploader = file_info.get('uploader', 'Desconocido')
                display = f"{filename:<40} (Subido por: {uploader})"
                self.files_listbox.insert(tk.END, display)
    
    # --- [ Envío de Archivos ] ---
    def select_file(self):
        """Permite seleccionar un archivo o carpeta para subir."""
        # Crear un diálogo personalizado que permita seleccionar tanto archivos como carpetas
        dialog = Toplevel(self.root)
        dialog.title("Seleccionar Archivo o Carpeta")   
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="¿Qué deseas subir?", font=('Arial', 12)).pack(pady=20)
        
        def select_single_file():
            file_path = filedialog.askopenfilename()
            if file_path:
                self.send_file(file_path)
            dialog.destroy()
        
        def select_folder():
            folder_path = filedialog.askdirectory()
            if folder_path:
                self.send_file(folder_path)
            dialog.destroy()
        
        tk.Button(dialog, text="📄 Seleccionar Archivo", command=select_single_file, width=25).pack(pady=5)
        tk.Button(dialog, text="📁 Seleccionar Carpeta", command=select_folder, width=25).pack(pady=5)

    def send_file(self, file_path):
        """Envía un archivo o una carpeta con todo su contenido."""
        if os.path.isfile(file_path):
            # Es un archivo individual
            self._send_single_file(file_path)
        elif os.path.isdir(file_path):
            # Es una carpeta, enviar todo su contenido
            self._send_folder(file_path)
        else:
            messagebox.showerror("Error", "La ruta no es válida.")

    def _send_single_file(self, file_path):
        """Envía un archivo individual."""
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

    def _send_folder(self, folder_path):
        """Envía una carpeta con todo su contenido."""
        folder_name = os.path.basename(folder_path.rstrip(os.sep))
        dest_folder = os.path.join(MULTIDESK_DIR, folder_name)

        try:
            if self.is_host:
                # Host: copiar la carpeta directamente
                if os.path.exists(dest_folder):
                    shutil.rmtree(dest_folder)
                shutil.copytree(folder_path, dest_folder)
                self.register_upload(folder_name, self.current_user)
                messagebox.showinfo("Carpeta enviada", f"Se agregó la carpeta '{folder_name}' con todo su contenido.")
            else:
                # Cliente: comprimir y enviar la carpeta
                self._send_folder_as_client(folder_path, folder_name, dest_folder)
        except Exception as e:
            messagebox.showerror("Error", f"Error al enviar la carpeta: {e}")
            self.update_debug_info(f'Error al enviar carpeta: {e}', is_error=True)

    def _send_folder_as_client(self, folder_path, folder_name, dest_folder):
        """Envía una carpeta desde el cliente comprimiéndola primero."""
        import zipfile
        
        try:
            # Crear un archivo ZIP temporal
            zip_path = os.path.join(MULTIDESK_DIR, f"{folder_name}.zip")
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, os.path.dirname(folder_path))
                        zipf.write(file_path, arcname)
            
            # Enviar el ZIP
            with open(zip_path, 'rb') as f:
                data = f.read()
            
            url = f'http://{self.host_ip}:{self.port}/'
            zip_filename = f"{folder_name}.zip"
            headers = {'X-Filename': urllib.parse.quote(zip_filename), 
                       'X-Client-Ip': self.local_ip, 
                       'X-Username': self.current_user}
            
            r = self.session.post(url, data=data, headers=headers)
            
            # Limpiar el ZIP temporal local
            os.remove(zip_path)
            
            if r.status_code == 200:
                messagebox.showinfo("Carpeta enviada", f"Se subió la carpeta '{folder_name}' comprimida como ZIP.")
                self.update_debug_info(f"✓ Carpeta '{folder_name}' subida exitosamente como ZIP")
            else:
                self.update_debug_info(f"Fallo al subir carpeta. Código HTTP: {r.status_code}", is_error=True)
        except Exception as e:
            self.update_debug_info(f'Error al enviar carpeta comprimida: {e}', is_error=True)

    def _handle_drop_event(self, data):
        """Handler for tkinterdnd2 drop events. `data` is a string like '{C:/path1} {C:/path2}'"""
        try:
            parts = data.split()
            paths = [p.strip('{}') for p in parts if p.strip('{}')]
            self._process_dropped_paths(paths)
        except Exception as e:
            self.update_debug_info(f"Error parsing drop data: {e}", is_error=True)

    def _process_dropped_paths(self, paths):
        """Process a list of filesystem paths dropped onto the Multi-Square."""
        if not paths:
            return
        
        # Count valid files and folders
        valid_items = []
        invalid_items = []
        
        for p in paths:
            p = p.strip()
            # On Windows, paths may be quoted
            if p.startswith('"') and p.endswith('"'):
                p = p[1:-1]
            if os.path.exists(p):
                valid_items.append(p)
            else:
                invalid_items.append(p)
        
        # Report status
        print(f"[DROP] Processed {len(paths)} path(s): {len(valid_items)} valid, {len(invalid_items)} invalid")
        
        # Process valid files and folders
        for p in valid_items:
            try:
                item_type = "carpeta" if os.path.isdir(p) else "archivo"
                print(f"[DROP] Sending {item_type}: {os.path.basename(p)}")
                self.send_file(p)
            except Exception as e:
                self.update_debug_info(f"Error al enviar elemento arrastrado '{p}': {e}", is_error=True)
        
        # Report invalid files
        for p in invalid_items:
            self.update_debug_info(f"Ruta arrastrada no existe: {p}", is_error=True)
        
        # Show summary message
        if valid_items:
            summary = f"✓ Se procesaron {len(valid_items)} elemento(s)"
            if invalid_items:
                summary += f" ({len(invalid_items)} rutas inválidas)"
            print(f"[DROP] {summary}")
            self.update_debug_info(summary)

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
        """Copia el archivo seleccionado a la carpeta de Descargas del usuario."""
        try:
            # 1. Obtiene el nombre real del archivo
            selected_indices = self.files_listbox.curselection()
            if not selected_indices:
                messagebox.showinfo("Error", "Selecciona un archivo para copiar a Descargas.")
                return

            text = self.files_listbox.get(selected_indices[0])
            # Extrae el nombre mostrado (soporta nombres con espacios)
            files_real = [f for f in os.listdir(MULTIDESK_DIR)]
            filename_real = next((f for f in files_real if text.startswith(f)), None)

            if not filename_real:
                messagebox.showerror("Error", "No se pudo identificar el archivo seleccionado.")
                return

            # Ruta de origen en la carpeta sincronizada (ya descargada)
            src_path = os.path.join(MULTIDESK_DIR, filename_real)
            if not os.path.exists(src_path):
                messagebox.showerror("Error", f"El archivo '{filename_real}' no está disponible localmente. Espera a que la sincronización lo descargue.")
                return

            # Determina carpeta Descargas y crea si no existe
            home = os.path.expanduser('~')
            if sys.platform.startswith('linux'):
                downloads_dir = os.path.join(home, 'Descargas')
                if not os.path.exists(downloads_dir):
                    downloads_dir = os.path.join(home, 'Downloads')
            else:
                downloads_dir = os.path.join(home, 'Downloads')

            os.makedirs(downloads_dir, exist_ok=True)

            dest_download_path = os.path.join(downloads_dir, filename_real)
            try:
                shutil.copy2(src_path, dest_download_path)
                messagebox.showinfo("Copiado a Descargas", f"'{filename_real}' fue copiado a: {dest_download_path}")
                self.update_debug_info(f"Copia a Descargas completada: {filename_real}")
                self.update_files()
            except Exception as e:
                self.update_debug_info(f"Error al copiar a Descargas: {e}", is_error=True)
                messagebox.showerror("Error", f"No se pudo copiar el archivo a Descargas: {e}")

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