import requests
import os

def get_config():
    ip = input("Ingrese la IP del host: ").strip()
    download_dir = input("Ingrese la ruta de descarga (ENTER para 'Descargas'): ").strip()
    if not download_dir:
        download_dir = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.isdir(download_dir):
        os.makedirs(download_dir)
    return ip, download_dir

def download_file(ip, download_dir):
    filename = input("Nombre del archivo a descargar (ejemplo: texto.txt): ").strip()
    url = f"http://{ip}:8000/{filename}"
    dest_path = os.path.join(download_dir, filename)
    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open(dest_path, 'wb') as f:
                f.write(response.content)
            print(f"Descargado: {dest_path}")
        else:
            print(f"Error: No se pudo descargar el archivo ({response.status_code})")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    ip, download_dir = get_config()
    while True:
        download_file(ip, download_dir)
        again = input("¿Descargar otro archivo? (s/n): ").strip().lower()
        if again != 's':
            break