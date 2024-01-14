use address_monitor::AddressMonitor;
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use domain::{
    base::{Dname, Question, Rtype, ToDname},
    resolv::stub,
};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use serde::Deserialize;
use std::{net::IpAddr, path::PathBuf, str::FromStr, time::Duration};
use tokio::{net::lookup_host, time::sleep};
use tracing::{info, warn};

pub mod dnsupdate;
use crate::dnsupdate::Key;

pub mod address_monitor;
pub mod certstore;

#[derive(Debug, Deserialize)]
struct LetsEncryptConfig {
    contacts: Vec<String>,
    #[serde(default)]
    production: bool,
    store: PathBuf,
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

async fn query_server<N: ToDname, Q: Into<Question<N>>>(
    server: &str,
    question: Q,
) -> Result<stub::Answer> {
    let mut addr = lookup_host(format!("{}:53", server)).await?;
    let addr = addr
        .next()
        .ok_or_else(|| anyhow!("Couldn't resolv dns server"))?;

    let conf = stub::conf::ServerConf::new(addr, stub::conf::Transport::Udp);
    let mut resolvconf = stub::conf::ResolvConf::new();
    resolvconf.servers.push(conf);
    let stub = domain::resolv::StubResolver::from_conf(resolvconf);

    Ok(stub.query(question).await?)
}

async fn ensure_txt_is_on_server(server: &str, name: &str, value: &str) -> Result<()> {
    'retry: loop {
        let answer = query_server(server, (Dname::<Vec<u8>>::from_str(name)?, Rtype::Txt))
            .await
            .context("Failed to query server")?;
        let answer = answer.answer().context("Invalid txt answer from server")?;
        for record in answer.limit_to_in::<domain::rdata::Txt<_>>() {
            let Ok(record) = record else {warn!("Invalid txt reply"); break} ;
            let txt = record.data().to_string();
            if txt == value {
                info!("Update TXT value present on {}", server);
                break 'retry;
            } else {
                info!("Oudated TXT value present on {}", server);
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
        (Dname::<Vec<u8>>::from_str(&config.zone)?, Rtype::Ns),
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

async fn letsencrypt(config: &Config, le: &LetsEncryptConfig) -> Result<(String, String)> {
    let contacts: Vec<&str> = le.contacts.iter().map(|s| s.as_str()).collect();

    let url = if le.production {
        LetsEncrypt::Production.url()
    } else {
        LetsEncrypt::Staging.url()
    };
    let account = Account::create(
        &NewAccount {
            contact: contacts.as_slice(),
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        url,
    )
    .await?;

    let identifier = Identifier::Dns(config.hostname.clone());
    let (mut order, state) = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .await?;

    info!("order state: {:#?}", state);
    let authorizations = order.authorizations(&state.authorizations).await?;
    println!("=> {:?}", authorizations);

    for authz in &authorizations {
        match &authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            s => bail!("Unhandled authorization status: {:?}", s),
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| anyhow!("No dns01 challenge found"))?;

        let challenge_name = format!("_acme-challenge.{}", &config.hostname);
        let challenge_value = order.key_authorization(challenge).dns_value();

        let mut update = dnsupdate::Update::new(&config.server, &config.zone, config.key.clone());
        // Very short time to live to get it flushed out early
        update.txt_update(&challenge_name, 60, &challenge_value)?;
        update.update().await?;

        for i in 0.. {
            match ensure_txt_is_everywhere(config, &challenge_name, &challenge_value).await {
                Ok(_) => {
                    order.set_challenge_ready(&challenge.url).await?;
                    break;
                }
                e if i < 128 => warn!("Failed to ensure txt records: {e:?}"),
                Err(e) => return Err(e),
            }
            tokio::time::sleep(Duration::from_secs(120)).await;
        }
    }

    let state = loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let state = order.state().await?;
        if matches!(state.status, OrderStatus::Ready | OrderStatus::Invalid) {
            break state;
        }
    };

    // Done; we can clear the TXT record
    let mut update = dnsupdate::Update::new(&config.server, &config.zone, config.key.clone());
    update.clear_txt(&format!("_acme-challenge.{}", &config.hostname))?;
    update.update().await?;

    info!("Certificate order state {:?}", state);

    if state.status == OrderStatus::Ready {
        let mut params = CertificateParams::new([config.hostname.clone()]);
        params.distinguished_name = DistinguishedName::new();
        let cert = Certificate::from_params(params)?;
        let csr = cert.serialize_request_der()?;

        let cert_chain_pem = order.finalize(&csr, &state.finalize).await?;
        Ok((cert_chain_pem, cert.serialize_private_key_pem()))
    } else {
        bail!("Failed to retrieve certificate")
    }
}

async fn letsencrypt_loop(config: &Config, le: &LetsEncryptConfig) -> Result<()> {
    let store = certstore::CertStore::new(config.hostname.clone(), le.store.clone());

    loop {
        store.cleanup_expired_certificates().await?;
        if let Some(duration) = store.duration_till_renewal().await {
            info!("Renewing certificate in {}s", duration.as_secs());
            sleep(duration).await;
        }
        info!("Renewing certificate");
        match letsencrypt(config, le).await {
            Ok((chain, key)) => store.insert_certificate(chain, key).await?,
            Err(e) => {
                warn!("Failed to get new letsencrypt certificate: {e:?}");
                warn!("Retrying in 15 minutes");
                tokio::time::sleep(Duration::from_secs(60 * 16)).await;
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
            if a < b {
                a
            } else {
                b
            }
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let opts = Opts::parse();

    let config = tokio::fs::read(opts.config).await?;
    let config: Config = serde_yaml::from_slice(&config)?;

    let monitor = monitor_address(&config);

    if let Some(le) = &config.letsencrypt {
        let le_loop = letsencrypt_loop(&config, le);

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
