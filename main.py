import http.server
import socketserver
import os
import cgi

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

    def list_files_page(self):
        """Genera un HTML con los archivos disponibles y un formulario de subida"""
        files = os.listdir(self.base_dir)
        files = [f for f in files if os.path.isfile(os.path.join(self.base_dir, f))]

        html = """
        <html>
        <head><title>Servidor de Archivos</title></head>
        <body>
        <h1>Servidor de Archivos</h1>
        <h2>Subir archivo</h2>
        <form enctype="multipart/form-data" method="post">
            <input type="file" name="file">
            <input type="submit" value="Subir">
        </form>
        <h2>Archivos disponibles</h2>
        <ul>
        """
        for f in files:
            html += f'<li><a href="/{f}">{f}</a></li>'
        html += "</ul></body></html>"
        return html.encode("utf-8")

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(self.list_files_page())
        else:
            return super().do_GET()

    def do_POST(self):
        """Maneja subida de archivos"""
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={"REQUEST_METHOD": "POST"}
        )
        if "file" in form:
            uploaded_file = form["file"]
            filename = os.path.basename(uploaded_file.filename)
            filepath = os.path.join(self.base_dir, filename)
            with open(filepath, "wb") as f:
                f.write(uploaded_file.file.read())
            self.send_response(303)
            self.send_header("Location", "/")  # redirige al index
            self.end_headers()
        else:
            self.send_error(400, "No se envió archivo")

if __name__ == "__main__":
    base_dir = get_base_directory()
    handler = lambda *args, **kwargs: CustomHandler(*args, base_dir=base_dir, **kwargs)
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Sirviendo archivos desde: {base_dir} en el puerto {PORT}")
        httpd.serve_forever()
