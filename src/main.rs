use address_monitor::AddressMonitor;
use anyhow::{Context, Result, anyhow, bail};
use certstore::CertStore;
use clap::Parser;
use domain::{
    base::{Name, Question, Rtype, ToName},
    resolv::stub,
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType,
    Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::ErrorKind, net::IpAddr, path::PathBuf, time::Duration};
use tokio::{io::AsyncWriteExt, net::lookup_host, time::sleep};
use tracing::{info, warn};
use x509_parser::prelude::{ParsedExtension, X509Certificate};

pub mod dnsupdate;
use crate::dnsupdate::Key;

pub mod address_monitor;
pub mod certstore;

#[derive(Debug, Deserialize)]
struct LetsEncryptConfig {
    contacts: BTreeSet<String>,
    profile: Option<String>,
    #[serde(default)]
    production: bool,
    store: PathBuf,
}

static ACCOUNT_FILENAME: &str = "account.yml";

#[derive(Serialize, Deserialize)]
struct LeAccount {
    contacts: BTreeSet<String>,
    directory: String,
    credentials: AccountCredentials,
}

impl LetsEncryptConfig {
    fn directory(&self) -> &'static str {
        if self.production {
            LetsEncrypt::Production.url()
        } else {
            LetsEncrypt::Staging.url()
        }
    }

    async fn get_existing_account(&self) -> Result<Option<Account>> {
        let account_path = self.store.join(ACCOUNT_FILENAME);

        let data = match tokio::fs::read(&account_path).await {
            Ok(data) => data,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => bail!(
                "Failed to open account file ({}): {e}",
                account_path.display()
            ),
        };

        let stored: LeAccount = serde_yaml::from_slice(&data)
            .with_context(|| format!("Failed to parse account from: {}", account_path.display()))?;
        if self.directory() != stored.directory {
            bail!("Saved account directory doesn't match expected directory");
        }

        info!("Loading stored account");
        let account = Account::builder()?
            .from_credentials(stored.credentials)
            .await?;

        if self.contacts != stored.contacts {
            info!("Updating account contacts to match config");
            let contacts: Vec<_> = self.contacts.iter().map(|s| s.as_str()).collect();
            // We have to reparse as the credential data isn't clone :/
            let stored: LeAccount = serde_yaml::from_slice(&data).with_context(|| {
                format!("Failed to parse account from: {}", account_path.display())
            })?;
            account
                .update_contacts(&contacts)
                .await
                .context("Failed to synchronize updated contacts")?;
            self.save_credentials(stored.credentials)
                .await
                .context("Failed to store updated account")?;
        }
        Ok(Some(account))
    }

    async fn update_account_key(&self, account: &mut Account) -> Result<()> {
        info!("Updating LE account key");
        let creds = account
            .update_key()
            .await
            .context("Failed to update account key")?;
        self.save_credentials(creds).await?;
        Ok(())
    }

    async fn save_credentials(&self, credentials: AccountCredentials) -> Result<()> {
        tokio::fs::create_dir_all(&self.store)
            .await
            .context("Failed to create store directory")?;

        let a = serde_yaml::to_string(&LeAccount {
            contacts: self.contacts.clone(),
            directory: self.directory().to_string(),
            credentials,
        })
        .context("Serializing le account data")?;

        let account_path = self.store.join(ACCOUNT_FILENAME);
        let mut file = tokio::fs::OpenOptions::new()
            .mode(0o600)
            .create(true)
            .write(true)
            .truncate(true)
            .open(account_path)
            .await
            .context("Failed to open account file")?;
        file.write_all(a.as_bytes())
            .await
            .context("Failed to write to account file")?;
        file.flush().await.context("Failed to flush account file")?;
        Ok(())
    }

    async fn get_new_account(&self) -> Result<Account> {
        let contacts: Vec<_> = self.contacts.iter().map(|s| s.as_str()).collect();
        info!("Setting up new account on {}", self.directory());
        let (account, credentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory().to_string(),
                None,
            )
            .await
            .context("Failed to create account")?;

        self.save_credentials(credentials).await?;

        Ok(account)
    }
}

#[derive(Debug, Deserialize)]
struct AddressConfig {
    #[serde(default)]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct AddressesConfig {
    ipv4: AddressConfig,
    ipv6: AddressConfig,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    server: String,
    zone: String,
    hostname: String,
    key: Key,
    letsencrypt: Option<LetsEncryptConfig>,
    addresses: AddressesConfig,
}

async fn query_server<N: ToName, Q: Into<Question<N>>>(
    server: &str,
    question: Q,
) -> Result<stub::Answer> {
    let mut addr = lookup_host(format!("{}:53", server)).await?;
    let addr = addr
        .next()
        .ok_or_else(|| anyhow!("Couldn't resolv dns server"))?;

    let conf = stub::conf::ServerConf::new(addr, stub::conf::Transport::UdpTcp);
    let mut resolvconf = stub::conf::ResolvConf::new();
    resolvconf.servers.push(conf);
    let stub = domain::resolv::StubResolver::from_conf(resolvconf);

    Ok(stub.query(question).await?)
}

async fn ensure_txt_is_on_server(server: &str, name: &str, value: &str) -> Result<()> {
    'retry: loop {
        let answer = query_server(server, (Name::vec_from_str(name)?, Rtype::TXT))
            .await
            .context("Failed to query server")?;
        let answer = answer.answer().context("Invalid txt answer from server")?;
        for record in answer.limit_to_in::<domain::rdata::Txt<_>>() {
            let Ok(record) = record else {
                warn!("Invalid txt reply");
                break;
            };
            let txt = record.data();
            if txt.as_flat_slice().unwrap_or_default() == value.as_bytes() {
                info!("Update TXT value present on {}", server);
                break 'retry;
            } else {
                info!("Outdated TXT value present on {} ({})", server, txt);
            }
        }
        info!("Record not yet present on {}", server);
        // DNS secondaries take a while, so only check at a leisurely pace
        tokio::time::sleep(Duration::from_secs(120)).await;
    }
    Ok(())
}

async fn ensure_txt_is_everywhere(config: &Config, name: &str, value: &str) -> Result<()> {
    info!("Going to check if {name} is updated on all nameservers");
    let answer = query_server(
        &config.server,
        (Name::vec_from_str(&config.zone)?, Rtype::NS),
    )
    .await
    .context("Failed to query nameservers")?;
    let answer = answer.answer().context("No valid nameserver answer")?;
    for record in answer.limit_to_in::<domain::rdata::Ns<_>>() {
        let record = record.context("Invalid NS answer")?;
        let nameserver = record.data().nsdname().to_string();
        info!("Going to check if {name} is updated on {nameserver}");
        ensure_txt_is_on_server(&nameserver, name, value).await?;
    }

    Ok(())
}

fn setup_order<'a>(
    identifiers: &'a [Identifier],
    profile: Option<&'a str>,
    replaces: Option<CertificateIdentifier<'a>>,
) -> NewOrder<'a> {
    let order = NewOrder::new(identifiers);
    let order = if let Some(profile) = profile {
        info!("Creating Order with profile: {profile}");
        order.profile(profile)
    } else {
        order
    };

    if let Some(replaces) = replaces {
        info!("Replacing old certificate");
        order.replaces(replaces)
    } else {
        order
    }
}
async fn do_request_certificate(
    account: &Account,
    profile: Option<&str>,
    config: &Config,
    x509: Option<&X509Certificate<'_>>,
) -> Result<(String, String)> {
    let identifiers = &[Identifier::Dns(config.hostname.clone())];
    let old = x509.and_then(|x| x509_to_identifier(x));

    let order = setup_order(identifiers, profile, old);
    let mut order = match account.new_order(&order).await {
        Err(instant_acme::Error::Unsupported(e)) => {
            warn!("Unsupported: {e}, retrying without replacement");
            let order = setup_order(identifiers, profile, None);
            account.new_order(&order).await
        }
        Err(instant_acme::Error::Api(ref p @ instant_acme::Problem { ref r#type, .. }))
            if r#type.as_deref() == Some("urn:ietf:params:acme:error:unauthorized") =>
        {
            warn!("unauthorized: {p}, retrying without replacement");
            let order = setup_order(identifiers, profile, None);
            account.new_order(&order).await
        }
        o => o,
    }?;

    info!("Certificate order state: {:#?}", order.state().status);
    let mut authorizations = order.authorizations();

    while let Some(mut authz) = authorizations.next().await.transpose()? {
        match &authz.status {
            AuthorizationStatus::Pending => {
                info!("Pending authorization");
            }
            AuthorizationStatus::Valid => {
                info!("Valid authorization");
                continue;
            }
            s => bail!("Unhandled authorization status: {:?}", s),
        }

        let mut challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow!("No dns01 challenge found"))?;

        let challenge_name = format!("_acme-challenge.{}", &config.hostname);
        let challenge_value = challenge.key_authorization().dns_value();

        let mut update = dnsupdate::Update::new(&config.server, &config.zone, config.key.clone());
        // Very short time to live to get it flushed out early
        update.txt_update(&challenge_name, 60, &challenge_value)?;
        update.update().await.context("DNS update")?;

        for i in 0.. {
            match ensure_txt_is_everywhere(config, &challenge_name, &challenge_value).await {
                Ok(_) => {
                    challenge.set_ready().await?;
                    break;
                }
                e if i < 128 => warn!("Failed to ensure txt records: {e:?}"),
                Err(e) => return Err(e),
            }
            tokio::time::sleep(Duration::from_secs(120)).await;
        }
    }

    let status = order.poll_ready(&RetryPolicy::default()).await?;

    if status == OrderStatus::Ready {
        let keypair = order.finalize().await?;
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        Ok((cert_chain_pem, keypair))
    } else {
        bail!("Failed to retrieve certificate")
    }
}

async fn request_certificate(
    account: &Account,
    profile: Option<&str>,
    config: &Config,
    x509: Option<&X509Certificate<'_>>,
) -> Result<(String, String)> {
    let ret = do_request_certificate(account, profile, config, x509).await;

    // Clear the TXT record in all cases
    info!("Clearing txt record");
    let mut update = dnsupdate::Update::new(&config.server, &config.zone, config.key.clone());
    if let Err(e) = update.clear_txt(&format!("_acme-challenge.{}", &config.hostname)) {
        warn!("Failed to setup clear txt update: {e}");
    } else if let Err(e) = update.update().await {
        warn!("Failed to sent clear update: {e}");
    }

    ret
}

// Time until the current certificate should be renewed; Returns None if it should be renewed
// immediately
fn duration_till_renewal(x509: &X509Certificate) -> Option<Duration> {
    let validity = x509.validity();
    let renew_slack = if let Some(period) = validity.not_after - validity.not_before {
        info!(
            "Total current certificate period {}, renewal after {}",
            period,
            period / 3 * 2
        );
        period.unsigned_abs() / 3
    } else {
        // If there is no validity period renew 7 days before expiry
        Duration::from_secs(7 * 24 * 3600)
    };

    let left = validity.time_to_expiration()?;
    info!(
        "Certificate will expire on {} in {}",
        validity.not_after, left
    );
    if left < renew_slack {
        None
    } else {
        let residual = left - renew_slack;
        info!("Time left to renewal: {}", residual);
        Some(residual.unsigned_abs())
    }
}

fn x509_to_identifier<'a>(x509: &X509Certificate<'a>) -> Option<CertificateIdentifier<'a>> {
    let aki = match x509.get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER) {
        Ok(aki) => aki,
        Err(e) => {
            warn!("Failed to parse Authority Key Identifier: {e}");
            None
        }
    }?;

    let identifier = match aki.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => aki.key_identifier.as_ref(),
        _ => None,
    }?;

    Some(CertificateIdentifier::new(
        identifier.0.into(),
        x509.raw_serial().into(),
    ))
}

async fn wait_for_renewal(account: &Account, x509: &X509Certificate<'_>) {
    let validity = x509.validity();
    info!("Current certificate valid until: {}", validity.not_after);

    if let Some(identifier) = x509_to_identifier(x509) {
        loop {
            let (renewal, refresh) = match account.renewal_info(&identifier).await {
                Ok(v) => v,
                Err(instant_acme::Error::Unsupported(s)) => {
                    warn!("Server doesn't support renewal info: {s}");
                    break;
                }
                Err(e) => {
                    warn!("Failed to get renewal request (retrying in 15m): {e}");
                    tokio::time::sleep(Duration::from_secs(60 * 15)).await;
                    continue;
                }
            };

            info!(
                "Renewal window: {} - {}",
                renewal.suggested_window.start, renewal.suggested_window.end
            );

            let diff = renewal.suggested_window.end - renewal.suggested_window.start;
            let diff = diff.try_into().unwrap_or_else(|_| {
                warn!("Failed to convert diff: {diff:?}");
                Duration::ZERO
            });

            let target = renewal.suggested_window.start + rand::random_range(Duration::ZERO..diff);
            info!("Renewal target from info: {target:?}");
            let remaining = target - std::time::SystemTime::now();
            if remaining < refresh {
                info!("sleeping till renewal: {remaining}");
                info!(
                    "sleeping till renewal: {}h{}m{}s",
                    refresh.as_secs() / 3600,
                    refresh.as_secs() % 3600 / 60,
                    refresh.as_secs() % 60,
                );
                sleep(remaining.try_into().unwrap_or_default()).await;
                return;
            } else {
                info!(
                    "Sleeping till renewal info refresh: {}h{}m{}s",
                    refresh.as_secs() / 3600,
                    refresh.as_secs() % 3600 / 60,
                    refresh.as_secs() % 60,
                );
                sleep(refresh).await;
            }
        }
    }

    if let Some(duration) = duration_till_renewal(x509) {
        sleep(duration).await;
    }
}

async fn letsencrypt_loop(
    account: Account,
    profile: Option<&str>,
    store: &CertStore,
    config: &Config,
    mut force_update: bool,
) -> Result<()> {
    loop {
        store.cleanup_expired_certificates().await?;
        let pem = store.current_cert().await;
        let x509 = pem.as_ref().and_then(|cert| match cert.parse_x509() {
            Ok(cert) => Some(cert),
            Err(e) => {
                info!("Failed to parse current certificate: {}", e);
                None
            }
        });

        if force_update {
            info!("Forcing certificate renewal");
        } else if let Some(x509) = x509.as_ref() {
            wait_for_renewal(&account, x509).await;
        } else {
            info!("No current certificate");
        };

        info!("Requesting certificate");
        match request_certificate(&account, profile, config, x509.as_ref()).await {
            Ok((chain, key)) => {
                store.insert_certificate(chain, key).await?;
                force_update = false;
            }
            Err(e) => {
                warn!("Failed to get new letsencrypt certificate: {e:?}");
                warn!("Retrying in 15 minutes");
                tokio::time::sleep(Duration::from_secs(60 * 15)).await;
            }
        }
    }
}

fn find_best_v4(m: &AddressMonitor) -> Option<Ipv4Network> {
    m.iter_addresses()
        .filter_map(|a| match a.ip {
            IpNetwork::V4(i) if !i.ip().is_link_local() => Some(i),
            _ => None,
        })
        .reduce(|a, b| {
            let a_ip = a.ip();
            let b_ip = b.ip();
            match (a_ip.is_private(), b_ip.is_private()) {
                (true, false) => return b,
                (false, true) => return a,
                _ => (),
            }
            // Deterministically pick the smallest if all else is equal
            if a < b { a } else { b }
        })
}

fn find_best_v6(m: &AddressMonitor) -> Option<Ipv6Network> {
    m.iter_addresses()
        .filter(|a| a.ip.is_ipv6())
        .reduce(|a, b| if a.ip < b.ip { a } else { b })
        .map(|a| match a.ip {
            IpNetwork::V4(_) => unreachable!("Not an ipv6 address"),
            IpNetwork::V6(i) => i,
        })
}

async fn update_addresses(
    v4: Option<Ipv4Network>,
    v6: Option<Ipv6Network>,
    config: &Config,
) -> Result<()> {
    let mut update = dnsupdate::Update::new(&config.server, &config.zone, config.key.clone());
    if let Some(ip) = v4 {
        update.address_update(&config.hostname, 300, IpAddr::V4(ip.ip()))?;
    } else {
        update.clear_a(&config.hostname)?;
    }
    if let Some(ip) = v6 {
        update.address_update(&config.hostname, 300, IpAddr::V6(ip.ip()))?;
    } else {
        update.clear_aaaa(&config.hostname)?;
    }
    update.update().await?;
    Ok(())
}

async fn monitor_address(config: &Config) -> Result<()> {
    let mut am = AddressMonitor::new().await?;
    let mut current_best_v4 = None;
    let mut current_best_v6 = None;
    loop {
        let mut changed = false;
        let best_v4 = if config.addresses.ipv4.enabled {
            find_best_v4(&am)
        } else {
            None
        };

        if current_best_v4 != best_v4 {
            changed = true;
        }

        let best_v6 = if config.addresses.ipv6.enabled {
            find_best_v6(&am)
        } else {
            None
        };

        if current_best_v6 != best_v6 {
            changed = true;
        }

        if changed {
            if let Err(e) = update_addresses(best_v4, best_v6, config).await {
                warn!("Failed to update address: {e}");
                match tokio::time::timeout(Duration::from_secs(10), am.wait_for_event()).await {
                    Ok(Err(e)) => return Err(e.into()),
                    _ => continue,
                }
            } else {
                current_best_v4 = best_v4;
                current_best_v6 = best_v6;
            }
        }
        am.wait_for_event().await?;
    }
}

#[derive(clap::Parser, Debug, Clone)]
struct Opts {
    config: PathBuf,
    /// Force an update of the LE certificate on startup
    #[clap(short, long)]
    force_le_update: bool,
    /// Deactivate acme account and exit
    #[clap(long)]
    deactive_account: bool,
    /// Update acme account key at startup
    #[clap(long)]
    update_account_key: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let opts = Opts::parse();

    let config = tokio::fs::read(opts.config)
        .await
        .context("Failed to read config file")?;
    let config: Config = serde_yaml::from_slice(&config).context("Failed to parse config")?;

    if opts.deactive_account {
        let Some(le) = &config.letsencrypt else {
            bail!("Can't deactivate an account without a letsencrypt config");
        };
        let Some(a) = le.get_existing_account().await? else {
            bail!("No account found");
        };
        a.deactivate().await?;
        return Ok(());
    }

    let monitor = monitor_address(&config);

    if let Some(le) = &config.letsencrypt {
        let account = if let Some(mut a) = le.get_existing_account().await? {
            if opts.update_account_key {
                le.update_account_key(&mut a).await?
            }
            a
        } else {
            le.get_new_account()
                .await
                .context("Failed to create LE account:")?
        };

        for p in account.profiles() {
            info!("Available profile: {}: {}", p.name, p.description);
        }

        let store = CertStore::new(config.hostname.clone(), le.store.clone());
        let le_loop = letsencrypt_loop(
            account,
            le.profile.as_deref(),
            &store,
            &config,
            opts.force_le_update,
        );

        tokio::select! {
            m = monitor => {
                warn!("Address monitor exited: {:?}", m);
                return m;
            }
            l = le_loop => {
                warn!("Certificate loop exited: {:?}", l);
                return l;
            }
        }
    } else {
        monitor.await?;
    }

    Ok(())
}
