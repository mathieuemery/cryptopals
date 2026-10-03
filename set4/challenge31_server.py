# Implement and break HMAC-SHA1 with an artificial timing leak (Server)

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from primitives.hmac_sha1 import HMAC_SHA1
import time

HOST = "localhost"
PORT = 9000

# The key must be shared with the client
key = b'YELLOW SUBMARINE'

class RequestHandler(BaseHTTPRequestHandler):
    def insecure_compare(self, file, signature):
        """
        Validate the MAC byte-per-byte and add a small
        timing leak.
        """
        comp_sig = bytearray(HMAC_SHA1(key, file).bytes())
        signature = bytearray(signature)

        for i in range(len(comp_sig)):
            if comp_sig[i] != signature[i]:
                return False
            
            time.sleep(0.005)

        return True


    def do_GET(self):
        """
        Validate the route and that the signature is valid.
        """
        parsed = urlparse(self.path)

        if parsed.path != "/test":
            self.send_response(404)
            self.end_headers()
            return

        params = parse_qs(parsed.query)

        file = params.get("file", [None])[0]
        signature = params.get("signature", [None])[0]

        if file is None or signature is None:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing file or signature")
            return

        # The client sends the signature as hexadecimal.
        try:
            signature_bytes = bytes.fromhex(signature)
        except ValueError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Signature must be hexadecimal")
            return

        file_bytes = file.encode()

        valid = self.insecure_compare(file_bytes, signature_bytes)

        if valid:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Invalid signature")


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), RequestHandler)

    print(f"Server listening on http://{HOST}:{PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.server_close()
