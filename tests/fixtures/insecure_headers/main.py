"""
INSECURE HEADERS FIXTURE FOR TESTING.
Returns HTTP response completely lacking CSP, HSTS, X-Content-Type-Options, or X-Frame-Options.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class InsecureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # Deliberately expose server banner
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Insecure App</h1></body></html>")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 9099), InsecureHandler)
    server.serve_forever()
