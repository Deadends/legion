#!/usr/bin/env python3
"""Simple HTTP server with CORS and WASM headers"""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import sys

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        
        # WASM headers (for SharedArrayBuffer support)
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cross-Origin-Resource-Policy', 'cross-origin')
        
        SimpleHTTPRequestHandler.end_headers(self)
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

if __name__ == '__main__':
    port = 8000
    print(f'🚀 Starting server on http://localhost:{port}')
    print(f'📁 Serving from: {sys.path[0]}')
    print(f'✅ CORS enabled')
    print(f'✅ WASM headers enabled')
    print(f'\n🌐 Open: http://localhost:{port}\n')
    
    httpd = HTTPServer(('localhost', port), CORSRequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\n\n👋 Server stopped')
        sys.exit(0)
