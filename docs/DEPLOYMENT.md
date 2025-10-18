# Legion ZK Auth - Production Deployment Guide

## 🚀 Quick Start

### Prerequisites
- Rust 1.75+ (stable)
- Node.js 18+ (for WASM build)
- Redis 7+ (for session management)
- 8GB+ RAM (for ZK proof generation)
- HTTPS domain (required for WebAuthn)

### 1. Build Production Binaries

```bash
# Build server (optimized)
cd legion-server
cargo build --release --features redis

# Build WASM client (optimized)
cd ../wasm-client
wasm-pack build --target web --release

# Server binary: legion-server/target/release/legion-server
# WASM files: wasm-client/pkg/
```

### 2. Environment Configuration

Create `.env` file in `legion-server/`:

```env
# Server Configuration
RUST_LOG=info
LEGION_DATA_PATH=/var/lib/legion/data
REDIS_URL=redis://127.0.0.1:6379

# Security (optional)
ORACLE_PUBLIC_KEY=<your-32-byte-hex-key>

# Production Settings
RUST_BACKTRACE=0
```

### 3. Deploy Server

```bash
# Create data directory
sudo mkdir -p /var/lib/legion/data
sudo chown $USER:$USER /var/lib/legion/data

# Copy binary
sudo cp legion-server/target/release/legion-server /usr/local/bin/

# Create systemd service
sudo nano /etc/systemd/system/legion.service
```

**legion.service**:
```ini
[Unit]
Description=Legion ZK Authentication Server
After=network.target redis.service

[Service]
Type=simple
User=legion
Group=legion
WorkingDirectory=/var/lib/legion
Environment="LEGION_DATA_PATH=/var/lib/legion/data"
Environment="REDIS_URL=redis://127.0.0.1:6379"
ExecStart=/usr/local/bin/legion-server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Start service
sudo systemctl daemon-reload
sudo systemctl enable legion
sudo systemctl start legion
sudo systemctl status legion
```

### 4. Deploy Frontend

```bash
# Copy WASM files to web server
sudo cp -r wasm-client/pkg/* /var/www/legion/
sudo cp wasm-client/index.html /var/www/legion/
sudo cp wasm-client/welcome.html /var/www/legion/
```

### 5. Configure Nginx (HTTPS Required)

```nginx
server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;

    # CRITICAL: Headers for WASM SharedArrayBuffer
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header Cross-Origin-Resource-Policy "cross-origin" always;

    # Frontend
    location / {
        root /var/www/legion;
        index index.html;
        try_files $uri $uri/ =404;
    }

    # API proxy to backend
    location /api/ {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 600s;  # 10 min for k=16/18 proofs
    }
}
```

### 6. Configure Redis

```bash
# Edit redis.conf
sudo nano /etc/redis/redis.conf
```

Add:
```conf
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
```

```bash
sudo systemctl restart redis
```

## 🔒 Security Checklist

- [ ] HTTPS enabled (required for WebAuthn)
- [ ] Redis password set (`requirepass` in redis.conf)
- [ ] Firewall configured (only 443, 80 open)
- [ ] Server runs as non-root user
- [ ] Data directory has restricted permissions (700)
- [ ] CORS configured for your domain only
- [ ] Rate limiting enabled (nginx `limit_req`)
- [ ] Logs monitored (journalctl -u legion -f)

## 📊 Monitoring

```bash
# Check server logs
sudo journalctl -u legion -f

# Check Redis
redis-cli INFO stats

# Check disk usage
du -sh /var/lib/legion/data

# Check active sessions
redis-cli KEYS "legion:session:*" | wc -l
```

## 🔧 Performance Tuning

### Client-Side (k parameter)
- **k=12**: 10s proof (testing only)
- **k=14**: 60s proof (development)
- **k=16**: 4min proof (production) ✅ **RECOMMENDED**
- **k=18**: 15min proof (high security)

### Server-Side
```bash
# Increase file descriptors
ulimit -n 65536

# Optimize RocksDB
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 🚨 Troubleshooting

### "Timestamp too far from current time"
- Server allows ±10 minutes for k=16/18
- Check server/client clock sync: `timedatectl`

### "WebAuthn failed"
- Must use HTTPS (not localhost in production)
- Check browser console for errors
- Verify RP ID matches domain

### "Proof verification failed"
- Check k parameter matches (client and server)
- Verify Merkle root is current
- Check nullifier not already used

### "Redis connection failed"
- Verify Redis running: `systemctl status redis`
- Check REDIS_URL in .env
- Test connection: `redis-cli ping`

## 📦 Backup & Recovery

```bash
# Backup anonymity set (RocksDB)
tar -czf legion-backup-$(date +%Y%m%d).tar.gz /var/lib/legion/data

# Backup Redis sessions
redis-cli --rdb /backup/redis-dump.rdb

# Restore
tar -xzf legion-backup-20250101.tar.gz -C /var/lib/legion/
```

## 🔄 Updates

```bash
# Pull latest code
git pull origin main

# Rebuild
cd legion-server && cargo build --release --features redis
cd ../wasm-client && wasm-pack build --target web --release

# Deploy
sudo systemctl stop legion
sudo cp legion-server/target/release/legion-server /usr/local/bin/
sudo cp -r wasm-client/pkg/* /var/www/legion/
sudo systemctl start legion
```

## 📈 Scaling

### Horizontal Scaling
- Run multiple server instances behind load balancer
- Share Redis instance across all servers
- Mount shared RocksDB volume (NFS/EFS)

### Vertical Scaling
- 4 CPU cores minimum
- 8GB RAM for k=16
- 16GB RAM for k=18
- SSD for RocksDB (NVMe recommended)

## 🎯 Production Checklist

- [ ] Server built with `--release`
- [ ] WASM built with `--release`
- [ ] Redis configured and secured
- [ ] HTTPS certificate installed
- [ ] Systemd service configured
- [ ] Nginx reverse proxy configured
- [ ] Firewall rules applied
- [ ] Monitoring setup
- [ ] Backup strategy implemented
- [ ] Domain DNS configured
- [ ] WebAuthn RP ID matches domain
- [ ] Rate limiting enabled
- [ ] Logs rotation configured

## 📞 Support

- GitHub Issues: https://github.com/deadends/legion
- Documentation: https://github.com/deadends/legion
- Security: nantha.ponmudi@gmail.com
