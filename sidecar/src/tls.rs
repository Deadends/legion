use rustls::{ServerConfig, RootCertStore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use rustls::server::WebPkiClientVerifier;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, Context};
use tracing::info;
use rcgen::{Certificate as RcgenCert, CertificateParams, DistinguishedName};
use std::fs;

#[derive(Clone)]
pub struct TlsConfig {
    pub server_config: Arc<ServerConfig>,
    pub mtls_enabled: bool,
}

impl TlsConfig {
    pub fn new() -> Result<Self> {
        let tls_enabled = std::env::var("TLS_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true);

        if !tls_enabled {
            return Err(anyhow::anyhow!("TLS is disabled"));
        }

        let cert_path = std::env::var("TLS_CERT_PATH")
            .unwrap_or_else(|_| "/run/secrets/legion-cert.pem".to_string());
        let key_path = std::env::var("TLS_KEY_PATH")
            .unwrap_or_else(|_| "/run/secrets/legion-key.pem".to_string());

        // Auto-generate certificate if files don't exist
        if !Path::new(&cert_path).exists() || !Path::new(&key_path).exists() {
            info!("TLS certificate not found, generating dev certificate");
            Self::generate_dev_cert(&cert_path, &key_path)?;
        }

        let server_config = Self::load_server_config(&cert_path, &key_path)?;
        
        let mtls_enabled = std::env::var("MTLS_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        Ok(TlsConfig {
            server_config: Arc::new(server_config),
            mtls_enabled,
        })
    }

    fn generate_dev_cert(cert_path: &str, key_path: &str) -> Result<()> {
        // Create certificate parameters
        let mut params = CertificateParams::new(vec![
            "localhost".to_string(),
            "legion-sidecar".to_string(),
            "127.0.0.1".to_string(),
        ]);
        
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "legion-sidecar");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "Legion Dev");
        params.distinguished_name.push(rcgen::DnType::CountryName, "US");

        // Generate certificate
        let cert = RcgenCert::from_params(params)?;
        let cert_pem = cert.serialize_pem()?;
        let key_pem = cert.serialize_private_key_pem();

        // Create directory if needed
        if let Some(parent) = Path::new(cert_path).parent() {
            fs::create_dir_all(parent)?;
        }

        // Write files
        fs::write(cert_path, cert_pem)?;
        fs::write(key_path, key_pem)?;

        // Set secure permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [cert_path, key_path] {
                let mut perms = fs::metadata(path)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(path, perms)?;
            }
        }

        info!("Generated dev certificate at {} and {}", cert_path, key_path);
        Ok(())
    }

    fn load_server_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
        // Load certificate
        let cert_file = File::open(cert_path)
            .with_context(|| format!("Failed to open certificate file: {}", cert_path))?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain: Vec<CertificateDer> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| "Failed to parse certificate")?;

        // Load private key
        let key_file = File::open(key_path)
            .with_context(|| format!("Failed to open private key file: {}", key_path))?;
        let mut key_reader = BufReader::new(key_file);
        let mut keys: Vec<_> = pkcs8_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| "Failed to parse private key")?;

        if keys.is_empty() {
            return Err(anyhow::anyhow!("No private keys found"));
        }

        let private_key = PrivateKeyDer::Pkcs8(keys.remove(0));

        // Build server config
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .with_context(|| "Failed to build TLS config")?;

        info!("Loaded TLS certificate from {}", cert_path);
        Ok(config)
    }

    pub fn load_mtls_config(cert_path: &str, key_path: &str, ca_path: &str) -> Result<ServerConfig> {
        // Load server certificate and key
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain: Vec<CertificateDer> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()?;

        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let mut keys: Vec<_> = pkcs8_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()?;
        let private_key = PrivateKeyDer::Pkcs8(keys.remove(0));

        // Load CA certificate for client verification
        let ca_file = File::open(ca_path)?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer> = certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()?;

        let mut root_store = RootCertStore::empty();
        for ca_cert in ca_certs {
            root_store.add(ca_cert)?;
        }

        let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()?;

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(cert_chain, private_key)?;

        info!("Loaded mTLS configuration with CA from {}", ca_path);
        Ok(config)
    }
}