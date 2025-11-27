Proyecto en Python - MultiDesk 5.0 (LPR 5° 3° A-B, 2025)

Descripción:
MultiDesk 5.0 es una aplicación de escritorio con interfaz gráfica (GUI) desarrollada en Python, diseñada para la transferencia segura de archivos en una red local (LAN) o a través de Internet (configurando el puerto).

Su objetivo principal es proveer una solución simple y robusta para el intercambio de documentos bajo un esquema de Host y Cliente. Un usuario crea una "sala" (Host, ejecutando un servidor HTTP ligero) y otros usuarios se conectan (Clientes) para subir y descargar archivos.

Características Clave:
Word Code System: Un sistema de codificación que transforma la dirección IP y el puerto en un código de palabras fácil de recordar, simplificando la conexión.

Autenticación: Gestión de usuarios y contraseñas mediante SQLite y hashing seguro con hashlib.

Control de Archivos: Permite a los usuarios descargar y eliminar sus propias subidas, manteniendo un registro de la autoría de los archivos.

Modo Temporal: Opción para borrar automáticamente todos los archivos compartidos al cerrar la sala.

Integrantes:

Nombre: Monzón Rocío

Nombre: Augusto Kurtz

Nombre: Thiago López

Nombre: Andrés Ochoa

Requisitos:

Sistema Operativo: Windows 10/11 (La aplicación es un ejecutable autónomo)

Archivos: Solo requiere el archivo Multi-Desk_5.0.exe.

Nota: No es necesario tener Python instalado, ya que el ejecutable incluye todas las librerías necesarias.

Ejecución:

Descargar el archivo Multi-Desk_5.0.exe.

Moverlo a una carpeta de trabajo permanente (ej. C:\Users\...\MultiDesk).

Hacer doble clic en Multi-Desk_5.0.exe para iniciar la aplicación.

Al ejecutarse por primera vez, se crearán automáticamente la base de datos (multidesk.db) y la carpeta de archivos compartidos (MultiDesk/) junto al ejecutable.

<hr>

Estructura del Proyecto (Después de la Ejecución)
El ejecutable es un archivo autónomo que genera los archivos de datos a su lado para mantener la información persistente.

Ejecutables/
├── Multi-Desk_5.0.exe    # El programa principal (lo que se distribuye)
├── MultiDesk/            # Carpeta generada por la app para almacenar archivos compartidos
│   └── .upload_log.json  # Log de subidas para controlar la autoría
├── multidesk.db          # Base de datos SQLite que almacena los usuarios y hashes
├── README.md             # Este archivo
├── LICENSE               # Tipo de licencia
(Los directorios de desarrollo como src/, docs/ y tests/ permanecen en el repositorio Git, pero no se distribuyen al usuario final).

<hr>

Licencia
MIT License

✅ Recordá mantener este archivo actualizado con los avances del proyecto.
