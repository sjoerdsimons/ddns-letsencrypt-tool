use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::{info, warn};
use x509_parser::time::ASN1Time;

#[derive(Debug)]
pub struct CertStore {
    hostname: String,
    path: PathBuf,
}

impl CertStore {
    pub fn new(hostname: String, path: PathBuf) -> Self {
        Self { hostname, path }
    }

    fn host_path(&self) -> PathBuf {
        let mut path = self.path.clone();
        path.push(&self.hostname);
        path
    }

    pub async fn current_cert(&self) -> Option<x509_parser::pem::Pem> {
        let mut cert_path = self.host_path();
        cert_path.push("current");
        cert_path.push("chain.pem");
        let cert = match tokio::fs::read(cert_path).await {
            Ok(cert) => cert,
            Err(e) => {
                info!("Failed to read current certificate: {}", e);
                return None;
            }
        };

        match x509_parser::pem::parse_x509_pem(&cert) {
            Ok((_, pem)) => Some(pem),
            Err(e) => {
                info!("Failed to parse current certificate: {}", e);
                None
            }
        }
    }

    pub async fn cleanup_expired_certificates(&self) -> Result<()> {
        info!("Cleaning up certificates for {}", self.hostname);
        let hostpath = self.host_path();

        let current = match tokio::fs::canonicalize(hostpath.join("current")).await {
            Ok(p) => Some(p),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                warn!("Failed to resolve current certificate: {e}");
                None
            }
        };

        let mut r = match tokio::fs::read_dir(&hostpath).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        while let Some(entry) = r.next_entry().await.transpose() {
            if let Ok(entry) = entry {
                let Ok(t) = entry.metadata().await else {
                    continue;
                };
                if t.is_dir() {
                    info!("Looking at certificate {:?}", entry.file_name());
                    let cert_path = hostpath.join(entry.file_name());
                    if current.as_ref() == Some(&cert_path) {
                        info!(
                            "{:?} is the current certificate, not cleaning up",
                            entry.file_name()
                        );
                        continue;
                    }
                    let chain_path = cert_path.join("chain.pem");
                    let cert = match tokio::fs::read(chain_path).await {
                        Ok(cert) => cert,
                        Err(e) => {
                            info!("Failed to read current certificate: {}", e);
                            continue;
                        }
                    };

                    let pem = match x509_parser::pem::parse_x509_pem(&cert) {
                        Ok((_, pem)) => pem,
                        Err(e) => {
                            info!("Failed to parse pem: {}", e);
                            continue;
                        }
                    };

                    let x509 = match pem.parse_x509() {
                        Ok(cert) => cert,
                        Err(e) => {
                            info!("Failed to parse  certificate: {}", e);
                            continue;
                        }
                    };

                    let validity = x509.validity();
                    let now = ASN1Time::now();
                    if validity.not_before > now {
                        info!(
                            "{:?} not yet valid (assuming misconfigured host clock): now: {} NotBefore {}",
                            entry.file_name(),
                            now,
                            validity.not_before
                        );
                    } else if let Some(duration) = x509.validity().time_to_expiration() {
                        info!("{:?} still valid for {}", entry.file_name(), duration);
                    } else {
                        info!("{:?} no longer valid, removing", entry.file_name());
                        if let Err(e) = tokio::fs::remove_dir_all(&cert_path).await {
                            warn!("Couldn't remove {}: {}", cert_path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // Add public and key parts; both expected to be pem, public should be the full chain
    pub async fn insert_certificate(&self, chain: String, key: String) -> Result<()> {
        let (_data, pem) = x509_parser::pem::parse_x509_pem(chain.as_bytes())
            .context("Failed to parse public chain")?;

        let x509 = pem.parse_x509().context("Failed to parse x509 data")?;
        info!(
            "Inserting certificate issued by {} for {}",
            x509.issuer(),
            x509.subject()
        );
        let serial = x509.raw_serial_as_string();

        let hostpath = self.host_path();
        let mut certpath = hostpath.clone();
        certpath.push(serial);
        tokio::fs::create_dir_all(&certpath)
            .await
            .context("Failed to create directory for certifcate storage")?;

        let mut chain_path = certpath.clone();
        chain_path.push("chain.pem");
        tokio::fs::write(chain_path, chain)
            .await
            .context("Failed to write chain to disk")?;

        let mut key_path = certpath.clone();
        key_path.push("key.pem");
        tokio::fs::write(key_path, key)
            .await
            .context("Failed to write key to disk")?;

        let current_tmp = hostpath.join(".current.link");
        let current = hostpath.join("current");

        match tokio::fs::remove_file(&current_tmp).await {
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            e => e.context("Failed to remove temp symlink")?,
        }
        tokio::fs::symlink(&certpath, &current_tmp)
            .await
            .context("Failed to create temporary symlink")?;
        tokio::fs::rename(&current_tmp, &current)
            .await
            .context("Failed to put current symlink in place")?;

        Ok(())
    }
}
