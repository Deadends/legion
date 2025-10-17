# HTTP server with COOP/COEP headers for multi-threaded WASM
Write-Host "🌐 Starting web server with COOP/COEP headers..." -ForegroundColor Cyan
Write-Host "⚠️  Required for SharedArrayBuffer and multi-threading" -ForegroundColor Yellow

if (Get-Command python -ErrorAction SilentlyContinue) {
    Write-Host "✅ Server running on http://localhost:3000" -ForegroundColor Green
    python -c @"
from http.server import HTTPServer, SimpleHTTPRequestHandler
import sys

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cross-Origin-Resource-Policy', 'cross-origin')
        SimpleHTTPRequestHandler.end_headers(self)

print('Serving at http://localhost:3000')
HTTPServer(('', 3000), CORSRequestHandler).serve_forever()
"@
} else {
    Write-Host "❌ Python not found. Install Python 3" -ForegroundColor Red
}
