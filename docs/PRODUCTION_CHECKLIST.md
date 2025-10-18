# Production Deployment Checklist

## Pre-Deployment

### Code Quality
- [ ] All tests passing (`cargo test --workspace`)
- [ ] No compiler warnings (`cargo clippy`)
- [ ] Dependencies audited (`cargo audit`)
- [ ] Code reviewed by team
- [ ] Security review completed

### Build
- [ ] Server built with `--release` flag
- [ ] WASM built with `--release` flag
- [ ] Docker images built and tested
- [ ] Binary sizes optimized

### Configuration
- [ ] `.env` file configured
- [ ] Redis password set
- [ ] HTTPS certificates obtained
- [ ] Domain DNS configured
- [ ] WebAuthn RP ID matches domain

## Deployment

### Infrastructure
- [ ] Server provisioned (4+ CPU, 8+ GB RAM)
- [ ] SSD/NVMe storage for RocksDB
- [ ] Redis installed and configured
- [ ] Nginx installed and configured
- [ ] Firewall configured (only 80/443 open)

### Security
- [ ] HTTPS enabled (required for WebAuthn)
- [ ] SSL/TLS certificates valid
- [ ] Redis password protected
- [ ] Server runs as non-root user
- [ ] Data directory permissions restricted (700)
- [ ] CORS configured for your domain only
- [ ] Rate limiting enabled
- [ ] Security headers configured

### Services
- [ ] Systemd service created
- [ ] Service enabled on boot
- [ ] Service started successfully
- [ ] Health check passing
- [ ] Logs accessible

### Monitoring
- [ ] Log rotation configured
- [ ] Monitoring dashboard setup
- [ ] Alerts configured
- [ ] Backup strategy implemented
- [ ] Backup tested and verified

## Post-Deployment

### Testing
- [ ] Registration flow tested
- [ ] Authentication flow tested
- [ ] Session management tested
- [ ] WebAuthn working on target devices
- [ ] Load testing completed
- [ ] Penetration testing completed

### Performance
- [ ] Response times acceptable
- [ ] Proof generation time verified (k=16: ~4min)
- [ ] Redis memory usage monitored
- [ ] RocksDB disk usage monitored
- [ ] CPU/RAM usage within limits

### Documentation
- [ ] Deployment documented
- [ ] API documentation updated
- [ ] Runbook created
- [ ] Incident response plan documented
- [ ] Team trained on operations

### Compliance
- [ ] Privacy policy updated
- [ ] Terms of service updated
- [ ] GDPR compliance verified (if applicable)
- [ ] Security audit completed
- [ ] Penetration test report reviewed

## Ongoing Operations

### Daily
- [ ] Check service health
- [ ] Monitor error logs
- [ ] Check Redis memory usage
- [ ] Verify backup completion

### Weekly
- [ ] Review authentication metrics
- [ ] Check disk space
- [ ] Review security logs
- [ ] Update dependencies (if needed)

### Monthly
- [ ] Rotate logs
- [ ] Test backup restoration
- [ ] Review performance metrics
- [ ] Security patch updates

### Quarterly
- [ ] Security audit
- [ ] Penetration testing
- [ ] Disaster recovery drill
- [ ] Capacity planning review

## Emergency Contacts

- **On-Call Engineer**: [phone/email]
- **Security Team**: security@yourdomain.com
- **Infrastructure Team**: infra@yourdomain.com
- **Management**: [contact]

## Rollback Plan

If deployment fails:

1. Stop new service: `systemctl stop legion`
2. Restore previous binary: `cp /backup/legion-server /usr/local/bin/`
3. Restore data: `tar -xzf /backup/legion-backup-latest.tar.gz`
4. Start service: `systemctl start legion`
5. Verify health: `curl http://localhost:3001/health`
6. Notify team

## Success Criteria

- [ ] Health check returns 200 OK
- [ ] Users can register successfully
- [ ] Users can authenticate successfully
- [ ] Sessions work correctly
- [ ] No errors in logs
- [ ] Response times < 1s (excluding proof generation)
- [ ] Uptime > 99.9%

## Sign-Off

- [ ] Engineering Lead: _________________ Date: _______
- [ ] Security Lead: _________________ Date: _______
- [ ] Operations Lead: _________________ Date: _______
- [ ] Product Manager: _________________ Date: _______

---

**Deployment Date**: __________
**Deployed By**: __________
**Version**: __________
