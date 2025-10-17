# Serve with COOP/COEP headers for SharedArrayBuffer
Write-Host "🚀 Starting server with COOP/COEP headers..." -ForegroundColor Cyan

$html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Legion ZK - Multithreaded WASM</title>
</head>
<body>
    <h1>🔐 Legion ZK Authentication (Multithreaded)</h1>
    <p>Client-side ZK proof generation with Web Workers</p>
    <script type="module">
        import init from './pkg/wasm_client.js';
        await init();
        console.log('✅ Multithreaded WASM initialized');
    </script>
</body>
</html>
"@

$html | Out-File -FilePath "index_mt.html" -Encoding utf8

# Start Python server with custom headers
python -c @"
from http.server import HTTPServer, SimpleHTTPRequestHandler
class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cross-Origin-Resource-Policy', 'cross-origin')
        SimpleHTTPRequestHandler.end_headers(self)
HTTPServer(('', 3000), CORSRequestHandler).serve_forever()
"@
