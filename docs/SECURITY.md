# Security Policy

## 🔒 Security Architecture

Legion ZK Auth implements zero-knowledge authentication with the following guarantees:

### Cryptographic Security
- **ZK Proof System**: Halo2 PLONK (no trusted setup)
- **Soundness Error**: 2^-128 (forgery probability)
- **Hash Functions**: Blake3 (credentials), Poseidon (circuit)
- **Curves**: Pasta (Pallas/Vesta)
- **Key Derivation**: BIP-39 (24-word mnemonic)

### Privacy Guarantees
- **User Anonymity**: 1 of 2^20 (1,048,576) users
- **Device Anonymity**: 1 of 2^10 (1,024) devices per user
- **Hardware Binding**: WebAuthn TPM/Secure Enclave
- **Zero-Knowledge**: Server never learns identity

### Attack Resistance
- ✅ **Replay Attacks**: Prevented by nullifiers + timestamps
- ✅ **Session Theft**: Prevented by linkability tag binding
- ✅ **Credential Stuffing**: BIP-39 entropy + rate limiting
- ✅ **Timing Attacks**: Constant-time operations in circuit
- ✅ **Sybil Attacks**: Device binding + nullifier tracking

## 🚨 Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead, email: **security@yourdomain.com**

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours.

## 🛡️ Security Best Practices

### Deployment
1. **Always use HTTPS** (required for WebAuthn)
2. **Set Redis password** (`requirepass` in redis.conf)
3. **Run as non-root user** (systemd User=legion)
4. **Restrict file permissions** (chmod 700 /var/lib/legion/data)
5. **Enable firewall** (only 80/443 open)
6. **Configure rate limiting** (nginx limit_req)
7. **Monitor logs** (journalctl -u legion -f)
8. **Regular backups** (RocksDB + Redis)

### Client-Side
1. **Use k=16 minimum** in production (k=12/14 for testing only)
2. **Verify HTTPS** before authentication
3. **Clear localStorage** on logout
4. **Validate server responses**

### Server-Side
1. **Validate all inputs** (hex strings, field elements)
2. **Check timestamp freshness** (±10 minutes for k=16/18)
3. **Verify nullifier uniqueness** (prevent replay)
4. **Enforce session TTL** (Redis expiration)
5. **Log authentication attempts** (audit trail)

## 🔐 Cryptographic Parameters

### Production Settings (k=16)
- Circuit size: 2^16 = 65,536 rows
- Proof time: ~4 minutes
- Proof size: ~3.5 KB
- Security level: 128-bit
- Soundness error: 2^-128

### High Security (k=18)
- Circuit size: 2^18 = 262,144 rows
- Proof time: ~15 minutes
- Proof size: ~4 KB
- Security level: 128-bit
- Soundness error: 2^-128

## 🔍 Audit History

| Date | Auditor | Scope | Status |
|------|---------|-------|--------|
| 2025-01 | Internal | Full system review | ✅ Passed |

## 📋 Security Checklist

### Pre-Deployment
- [ ] Code review completed
- [ ] Dependencies audited (`cargo audit`)
- [ ] Secrets not in code
- [ ] HTTPS certificate valid
- [ ] Redis secured
- [ ] Rate limiting configured
- [ ] Monitoring setup

### Post-Deployment
- [ ] Penetration testing
- [ ] Load testing
- [ ] Log monitoring active
- [ ] Backup strategy tested
- [ ] Incident response plan
- [ ] Security updates scheduled

## 🚀 Responsible Disclosure

We follow a 90-day disclosure timeline:
1. **Day 0**: Vulnerability reported
2. **Day 1-7**: Acknowledge and validate
3. **Day 7-30**: Develop and test fix
4. **Day 30-60**: Deploy fix to production
5. **Day 60-90**: Public disclosure (coordinated)

## 🏆 Security Researchers

We appreciate security researchers who help improve Legion:
- Responsible disclosure
- Coordinated timeline
- Public acknowledgment (with permission)

## 📚 References

- [Halo2 Documentation](https://zcash.github.io/halo2/)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [BIP-39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [Blake3 Paper](https://github.com/BLAKE3-team/BLAKE3-specs)

## 📞 Contact

- Security: nantha.ponmudi@gmail.com
- GitHub: https://github.com/deadends/legion
