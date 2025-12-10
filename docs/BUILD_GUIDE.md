# Legion Build & Push Guide 🚀

## Problem: Podman Build Issues on Windows

You're experiencing: `Error: server probably quit: unexpected EOF`

This is a known Podman/WSL stability issue on Windows.

---

## ✅ Solution 1: Use Docker Desktop (Recommended)

### Install Docker Desktop
1. Download: https://www.docker.com/products/docker-desktop/
2. Install and start Docker Desktop
3. Build:

```bash
docker build -t docker.io/deadends/legion-server:1.0.0 -t docker.io/deadends/legion-server:latest -f docker/Dockerfile .
```

### Push to Docker Hub
```bash
# Login
docker login

# Push
docker push docker.io/deadends/legion-server:1.0.0
docker push docker.io/deadends/legion-server:latest
```

---

## ✅ Solution 2: GitHub Actions (Automatic)

### Setup (One-time)

1. **Add Docker Hub secrets to GitHub:**
   - Go to: https://github.com/Deadends/legion/settings/secrets/actions
   - Add `DOCKER_USERNAME`: `deadends`
   - Add `DOCKER_PASSWORD`: Your Docker Hub token

2. **Commit and push the workflow:**
```bash
git add .github/workflows/docker-build.yml
git commit -m "Add Docker build workflow"
git push origin main
```

3. **GitHub will automatically build and push!**
   - Check: https://github.com/Deadends/legion/actions
   - Images appear at: https://hub.docker.com/r/deadends/legion-server

### Trigger Manual Build
- Go to: https://github.com/Deadends/legion/actions
- Click "Build and Push Docker Images"
- Click "Run workflow"

---

## ✅ Solution 3: Fix Podman (Advanced)

### Increase Resources
```powershell
podman machine stop
podman machine set --cpus 4 --memory 8192
podman machine start
```

### Fix DNS
```powershell
podman machine ssh "echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf"
```

### Build with No Cache
```bash
podman build --no-cache --format docker -t docker.io/deadends/legion-server:latest -f docker/Dockerfile .
```

---

## 📦 After Building

### Update docker-compose.yml
```yaml
legion-server:
  image: docker.io/deadends/legion-server:latest  # Use pre-built image
  # Remove 'build:' section
```

### Update README.md
Add this section:

```markdown
## 🐳 Quick Deploy (Pre-built Image)

```bash
# Pull from Docker Hub
docker pull deadends/legion-server:latest

# Run with docker-compose
docker compose up -d
```

Users don't need to build - just pull and run!
```

---

## 🎯 Recommended Approach

**Use GitHub Actions** - It's:
- ✅ Free
- ✅ Automatic on every push
- ✅ Builds for multiple platforms (amd64, arm64)
- ✅ No local build issues
- ✅ Professional CI/CD

Just add the Docker Hub secrets and push!

---

## 📞 Need Help?

- Docker Desktop: https://docs.docker.com/desktop/
- GitHub Actions: https://docs.github.com/en/actions
- Docker Hub: https://hub.docker.com/
