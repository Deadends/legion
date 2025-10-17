#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cross-Origin-Resource-Policy', 'cross-origin')
        self.send_header('Access-Control-Allow-Origin', '*')
        SimpleHTTPRequestHandler.end_headers(self)

if __name__ == '__main__':
    print('🚀 Serving on http://localhost:8000')
    print('⚠️  COOP/COEP/CORP headers enabled for SharedArrayBuffer')
    print('📝 Check crossOriginIsolated in browser console (should be true)')
    HTTPServer(('', 8000), CORSRequestHandler).serve_forever()
