import http.server
import socketserver
import os

PORT = 8000

def get_base_directory():
	base_dir = input("Ingrese la ruta base de los archivos a servir: ").strip()
	if not os.path.isdir(base_dir):
		print("La ruta no existe o no es un directorio. Usando el directorio actual.")
		base_dir = os.getcwd()
	return base_dir

class CustomHandler(http.server.SimpleHTTPRequestHandler):
	def __init__(self, *args, base_dir=None, **kwargs):
		self.base_dir = base_dir or os.getcwd()
		super().__init__(*args, **kwargs)

	def do_GET(self):
		local_path = self.path.lstrip('/')
		file_path = os.path.join(self.base_dir, local_path)
		if os.path.isfile(file_path):
			self.send_response(200)
			self.send_header("Content-type", "application/octet-stream")
			self.send_header("Content-Length", str(os.path.getsize(file_path)))
			self.end_headers()
			with open(file_path, 'rb') as f:
				self.wfile.write(f.read())
		else:
			self.send_error(404)

if __name__ == "__main__":
	base_dir = get_base_directory()
	handler = lambda *args, **kwargs: CustomHandler(*args, base_dir=base_dir, **kwargs)
	with socketserver.TCPServer(("", PORT), handler) as httpd:
		print(f"Sirviendo archivos desde: {base_dir} en el puerto {PORT}")
		httpd.serve_forever()
