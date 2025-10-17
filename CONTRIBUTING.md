# Contributing to Legion

Thank you for your interest in contributing! This guide will help you get started.

## 🚀 Quick Start

```bash
# Fork and clone
git clone https://github.com/deadends/legion.git
cd legion

# Create branch
git checkout -b feature/amazing-feature

# Make changes and test
cargo test --workspace

# Commit and push
git commit -m "Add amazing feature"
git push origin feature/amazing-feature

# Open Pull Request
```

## 📋 Development Setup

### Prerequisites
- Rust 1.75+
- Redis 7.0+
- Git
- 8GB RAM recommended

### Local Environment
```bash
# Install dependencies
rustup update
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Start Redis
redis-server

# Run tests
cargo test --workspace

# Start development server
cd legion-server
cargo run --release --features redis
```

## 🎯 How to Contribute

### Reporting Bugs
1. Check existing issues
2. Create new issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details
   - Logs/screenshots

### Suggesting Features
1. Open discussion first
2. Explain use case
3. Provide examples
4. Consider alternatives

### Submitting Code
1. Fork repository
2. Create feature branch
3. Write tests
4. Update documentation
5. Submit pull request

## 📝 Code Standards

### Rust Style
```rust
// Use descriptive names
fn compute_merkle_proof() -> Result<Vec<Fp>> { }

// Document public APIs
/// Generates a zero-knowledge proof for authentication
pub fn generate_proof(circuit: AuthCircuit) -> Result<Vec<u8>> { }

// Handle errors properly
let result = operation().context("Failed to perform operation")?;
```

### Testing
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_generation() {
        // Arrange
        let circuit = create_test_circuit();
        
        // Act
        let proof = generate_proof(circuit).unwrap();
        
        // Assert
        assert_eq!(proof.len(), 3520);
    }
}
```

### Commit Messages
```
feat: Add Merkle tree caching
fix: Resolve deadlock in authentication
docs: Update deployment guide
test: Add integration tests for Redis
refactor: Simplify proof generation logic
perf: Optimize key pool allocation
```

## 🧪 Testing Requirements

All PRs must include:
- [ ] Unit tests for new code
- [ ] Integration tests if applicable
- [ ] All existing tests passing
- [ ] No clippy warnings

```bash
# Run full test suite
cargo test --workspace --release

# Run clippy
cargo clippy --all-targets -- -D warnings

# Check formatting
cargo fmt --all -- --check
```

## 📚 Documentation

Update documentation for:
- New features
- API changes
- Configuration options
- Breaking changes

Files to update:
- `README.md` - Overview and quick start
- `DEPLOYMENT.md` - Deployment instructions
- `docs/API.md` - API reference
- Code comments - Public APIs

## 🔍 Code Review Process

1. **Automated Checks**
   - CI tests must pass
   - No merge conflicts
   - Code formatted

2. **Manual Review**
   - Code quality
   - Test coverage
   - Documentation
   - Security implications

3. **Approval**
   - 1 approval required
   - Maintainer merge

## 🏗️ Project Structure

```
legion/
├── legion-server/       # Backend server (Axum, verifies proofs)
│   ├── src/
│   │   ├── main.rs      # Entry point
│   │   └── webauthn_handlers.rs
│   └── Cargo.toml
├── prover/              # ZK proof library (Halo2 circuits)
│   ├── src/
│   │   ├── auth_circuit.rs
│   │   ├── proof_generator.rs
│   │   └── ...
│   └── Cargo.toml
├── wasm-client/         # Frontend (Browser, generates proofs)
├── verifier/            # Verification utilities
├── sidecar/             # Optional TLS proxy
└── docs/                # Documentation
```

## 🎨 Areas for Contribution

### High Priority
- [ ] Performance optimizations
- [ ] Additional test coverage
- [ ] Documentation improvements
- [ ] Bug fixes

### Medium Priority
- [ ] New features (discuss first)
- [ ] Code refactoring
- [ ] Tooling improvements

### Good First Issues
Look for issues labeled `good-first-issue`:
- Documentation fixes
- Test additions
- Minor bug fixes
- Code cleanup

## 🔒 Security

**DO NOT** submit security vulnerabilities as public issues.

Report to: nantha.ponmudi@gmail.com

See [SECURITY.md](./SECURITY.md) for details.

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 💬 Communication

- **Issues**: Bug reports and feature requests
- **Discussions**: Questions and ideas
- **Pull Requests**: Code contributions
- **Email**: dev@yourdomain.com

## 🙏 Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

## ❓ Questions?

- Read the [README.md](./README.md)
- Check [existing issues](https://github.com/deadends/legion/issues)
- Ask in [discussions](https://github.com/deadends/legion/discussions)
- Email: nantha.ponmudi@gmail.com

---

**Thank you for contributing to Legion!** 🎉
