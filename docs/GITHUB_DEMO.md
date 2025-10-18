# Legion ZK Auth - GitHub Demo Setup

## 🎯 Goal: Showcase Your Zero-Knowledge Authentication System

This guide helps you demonstrate Legion on GitHub without needing a production server.

## 📦 What to Push to GitHub

### 1. Clean Up First

```bash
# Remove build artifacts and cache
cd legion
rm -rf target/
rm -rf wasm-client/pkg/
rm -rf wasm-client/node_modules/
rm -rf prover/legion_data/
rm -rf legion-server/target/

# Remove sensitive files
rm -f .env
rm -f *.log
```

### 2. Create .gitignore

Already exists, but verify it includes:
```
target/
wasm-client/pkg/
wasm-client/node_modules/
prover/legion_data/
.env
*.log
```

### 3. Push to GitHub

```bash
# Initialize git (if not already)
git init

# Add all files
git add .

# Commit
git commit -m "feat: Zero-Knowledge Authentication with Halo2 PLONK"

# Add remote (replace with your repo)
git remote add origin https://github.com/deadends/legion.git

# Push
git push -u origin main
```

## 🎬 Demo for Others

### Option 1: Local Demo (Recommended)

Share these instructions in your README:

```bash
# Clone the repo
git clone https://github.com/deadends/legion.git
cd legion

# Install Redis (required)
# macOS: brew install redis && redis-server
# Ubuntu: sudo apt install redis && redis-server
# Windows: https://redis.io/docs/getting-started/installation/install-redis-on-windows/

# Build and run server
cd legion-server
cargo run --release --features redis

# In another terminal, build WASM
cd wasm-client
wasm-pack build --target web --release

# Serve frontend (any HTTP server)
python3 -m http.server 8000
# Or: npx http-server -p 8000

# Open browser: http://localhost:8000
```

### Option 2: GitHub Pages (Frontend Only)

For showcasing the UI (without backend):

```bash
# Build WASM
cd wasm-client
wasm-pack build --target web --release

# Create gh-pages branch
git checkout --orphan gh-pages
git rm -rf .

# Copy built files
cp -r pkg/* .
cp index.html .
cp welcome.html .

# Commit and push
git add .
git commit -m "Deploy to GitHub Pages"
git push origin gh-pages

# Enable GitHub Pages in repo settings
# Settings → Pages → Source: gh-pages branch
```

**Note**: Backend won't work on GitHub Pages (static hosting only). This is just for UI showcase.

### Option 3: Video Demo

Record a demo video showing:
1. Registration flow
2. WebAuthn hardware key
3. ZK proof generation (4 min for k=16)
4. Anonymous authentication
5. Session verification

Upload to YouTube and link in README.

## 📝 Update README for Showcase

Add this section to your README.md:

```markdown
## 🎬 Live Demo

### Try It Locally

```bash
# 1. Install Redis
brew install redis && redis-server  # macOS
# sudo apt install redis && redis-server  # Linux

# 2. Run server
cd legion-server && cargo run --release --features redis

# 3. Build and serve frontend
cd ../wasm-client
wasm-pack build --target web --release
python3 -m http.server 8000

# 4. Open http://localhost:8000
```

### Demo Video

[Watch 5-minute demo on YouTube](https://youtube.com/your-video)

### Screenshots

![Registration](docs/screenshots/registration.png)
![Authentication](docs/screenshots/auth.png)
![Zero-Knowledge Proof](docs/screenshots/proof.png)
```

## 🎨 Make It Look Professional

### 1. Add Screenshots

```bash
mkdir -p docs/screenshots
# Take screenshots of your UI and save them
```

### 2. Add Architecture Diagram

Create `docs/architecture.png` showing:
- Client (Browser)
- ZK Proof Generation
- Server (Verifier)
- Merkle Trees
- Device Ring Signatures

### 3. Add Demo GIF

Use tools like:
- **Kap** (macOS): https://getkap.co/
- **ScreenToGif** (Windows): https://www.screentogif.com/
- **Peek** (Linux): https://github.com/phw/peek

Record 30-second GIF showing authentication flow.

### 4. Update README with Badges

```markdown
[![Demo](https://img.shields.io/badge/demo-live-success)](https://yourdomain.com)
[![Video](https://img.shields.io/badge/video-youtube-red)](https://youtube.com/your-video)
[![Stars](https://img.shields.io/github/stars/deadends/legion?style=social)](https://github.com/deadends/legion)
```

## 🚀 Optimize for GitHub Discovery

### 1. Add Topics

In GitHub repo settings, add topics:
- `zero-knowledge`
- `cryptography`
- `authentication`
- `halo2`
- `rust`
- `webauthn`
- `privacy`
- `zk-snarks`

### 2. Create GitHub Release

```bash
# Tag your version
git tag -a v1.0.0 -m "Initial release: Zero-Knowledge Authentication"
git push origin v1.0.0

# Create release on GitHub with:
# - Release notes
# - Pre-built binaries (optional)
# - Demo video link
```

### 3. Add Social Preview

Create `docs/social-preview.png` (1280x640px) showing:
- Legion logo
- "Zero-Knowledge Authentication"
- Key features

Upload in: Settings → Options → Social preview

## 📊 What People Want to See

### In README:
1. ✅ **What it does** (1 sentence)
2. ✅ **Why it's cool** (zero-knowledge!)
3. ✅ **How to try it** (simple commands)
4. ✅ **Architecture diagram**
5. ✅ **Demo video/GIF**
6. ✅ **Performance numbers** (k=16: 4min proof)
7. ✅ **Security guarantees** (2^-128 soundness)

### In Code:
1. ✅ **Clean structure** (already done)
2. ✅ **Good comments** (already done)
3. ✅ **Tests** (already done)
4. ✅ **Documentation** (already done)

## 🎯 Quick Push Checklist

- [ ] Clean build artifacts (`rm -rf target/`)
- [ ] Update README with demo instructions
- [ ] Add screenshots/GIFs
- [ ] Test locally one more time
- [ ] Commit and push to GitHub
- [ ] Add topics to repo
- [ ] Create release (v1.0.0)
- [ ] Share on Twitter/Reddit/HN

## 🔗 Share Your Work

Post on:
- **Twitter**: Tag @rustlang, #ZeroKnowledge, #Cryptography
- **Reddit**: r/rust, r/crypto, r/programming
- **Hacker News**: Show HN: Zero-Knowledge Authentication with Halo2
- **LinkedIn**: Professional network
- **Dev.to**: Write a blog post

## 📞 Get Feedback

Create GitHub Discussions:
- Ideas for improvement
- Questions about implementation
- Use cases
- Performance optimization

---

**Remember**: You're showcasing innovation, not running a production service. Focus on:
1. Clear explanation of what it does
2. Easy local demo
3. Beautiful presentation
4. Technical depth in docs
