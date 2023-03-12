use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use domain::base::message_builder::AuthorityBuilder;
use domain::rdata::Txt;
use domain::rdata::A;
use domain::tsig;
use serde::Deserialize;
use serde_with::base64::Base64;
use serde_with::serde_as;
use serde_with::DisplayFromStr;
use tracing::info;

use std::collections::HashSet;
use std::{net::IpAddr, str::FromStr};

use domain::{
    base::{
        iana::{Class, Opcode},
        Dname, MessageBuilder, Rtype,
    },
    rdata::Aaaa,
    tsig::Algorithm,
};

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct Key {
    id: String,
    #[serde_as(as = "DisplayFromStr")]
    algorithm: Algorithm,
    #[serde_as(as = "Base64")]
    secret: Vec<u8>,
}

impl TryInto<tsig::Key> for Key {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<domain::tsig::Key, Self::Error> {
        Ok(domain::tsig::Key::new(
            self.algorithm,
            &self.secret,
            Dname::from_str(&self.id)?,
            None,
            None,
        )?)
    }
}

#[derive(Debug, Clone)]
struct AddressUpdate {
    name: Dname<Vec<u8>>,
    ttl: u32,
    address: IpAddr,
}

#[derive(Debug, Clone)]
struct TxtUpdate {
    name: Dname<Vec<u8>>,
    ttl: u32,
    txt: String,
}

#[derive(Debug, Clone)]
pub struct Update {
    server: String,
    zone: String,
    key: Key,
    address: Vec<AddressUpdate>,
    txt: Vec<TxtUpdate>,
    clear: Vec<(Dname<Vec<u8>>, Rtype)>,
}

impl Update {
    pub fn new<S, Z>(server: S, zone: Z, key: Key) -> Self
    where
        S: Into<String>,
        Z: Into<String>,
    {
        Self {
            server: server.into(),
            zone: zone.into(),
            key,
            address: Vec::new(),
            txt: Vec::new(),
            clear: Vec::new(),
        }
    }

    pub fn address_update(&mut self, name: &str, ttl: u32, address: IpAddr) -> Result<()> {
        self.address.push(AddressUpdate {
            name: Dname::from_str(name)?,
            ttl,
            address,
        });
        Ok(())
    }

    pub fn clear_a(&mut self, name: &str) -> Result<()> {
        self.clear.push((Dname::from_str(name)?, Rtype::A));
        Ok(())
    }

    pub fn clear_aaaa(&mut self, name: &str) -> Result<()> {
        self.clear.push((Dname::from_str(name)?, Rtype::Aaaa));
        Ok(())
    }

    pub fn txt_update<T: Into<String>>(&mut self, name: &str, ttl: u32, txt: T) -> Result<()> {
        self.txt.push(TxtUpdate {
            name: Dname::from_str(name)?,
            ttl,
            txt: txt.into(),
        });
        Ok(())
    }

    pub fn clear_txt(&mut self, name: &str) -> Result<()> {
        self.clear.push((Dname::from_str(name)?, Rtype::Txt));
        Ok(())
    }

    fn hosts_with_a_records(&self) -> impl Iterator<Item = &Dname<Vec<u8>>> {
        let mut hosts = HashSet::new();
        for a in &self.address {
            if a.address.is_ipv4() {
                hosts.insert(&a.name);
            }
        }
        hosts.into_iter()
    }

    fn hosts_with_aaaa_records(&self) -> impl Iterator<Item = &Dname<Vec<u8>>> {
        let mut hosts = HashSet::new();
        for a in &self.address {
            if a.address.is_ipv6() {
                hosts.insert(&a.name);
            }
        }
        hosts.into_iter()
    }

    fn hosts_with_txt_records(&self) -> impl Iterator<Item = &Dname<Vec<u8>>> {
        let mut hosts = HashSet::new();
        for t in &self.txt {
            hosts.insert(&t.name);
        }
        hosts.into_iter()
    }

    fn delete_old(&self, builder: &mut AuthorityBuilder<Vec<u8>>) -> Result<()> {
        let empty =
            domain::base::octets::OctetsBuilder::freeze(std::borrow::Cow::<[u8]>::Borrowed(&[]));
        let empty = domain::base::UnknownRecordData::from_octets(Rtype::A, empty);
        for a in self.hosts_with_a_records() {
            info!("Deleting A for {}", a);
            builder.push((a, Class::Any, 0, empty.clone()))?;
        }
        for a in self.clear.iter().filter(|a| a.1 == Rtype::A) {
            info!("Deleting A for {}", a.0);
            builder.push((&a.0, Class::Any, 0, empty.clone()))?;
        }

        let empty =
            domain::base::octets::OctetsBuilder::freeze(std::borrow::Cow::<[u8]>::Borrowed(&[]));
        let empty = domain::base::UnknownRecordData::from_octets(Rtype::Aaaa, empty);
        for a in self.hosts_with_aaaa_records() {
            info!("Deleting AAAA for {}", a);
            builder.push((a, Class::Any, 0, empty.clone()))?;
        }
        for a in self.clear.iter().filter(|a| a.1 == Rtype::Aaaa) {
            info!("Deleting AAAA for {}", a.0);
            builder.push((&a.0, Class::Any, 0, empty.clone()))?;
        }

        let empty =
            domain::base::octets::OctetsBuilder::freeze(std::borrow::Cow::<[u8]>::Borrowed(&[]));
        let empty = domain::base::UnknownRecordData::from_octets(Rtype::Txt, empty);
        for a in self.hosts_with_txt_records() {
            info!("Deleting TXT for {}", a);
            builder.push((a, Class::Any, 0, empty.clone()))?;
        }
        for a in self.clear.iter().filter(|a| a.1 == Rtype::Txt) {
            info!("Deleting TXT for {}", a.0);
            builder.push((&a.0, Class::Any, 0, empty.clone()))?;
        }

        Ok(())
    }

    fn push_updates(&self, builder: &mut AuthorityBuilder<Vec<u8>>) -> Result<()> {
        for a in &self.address {
            info!("Updating: {:?}", a);
            match a.address {
                IpAddr::V4(v4) => builder.push((&a.name, a.ttl, A::new(v4)))?,
                IpAddr::V6(v6) => builder.push((&a.name, a.ttl, Aaaa::new(v6)))?,
            }
        }
        for t in &self.txt {
            info!("Updating: {:?}", t);
            builder.push((
                &t.name,
                t.ttl,
                Txt::<Vec<u8>>::from_slice(t.txt.as_bytes())?,
            ))?;
        }
        Ok(())
    }

    pub async fn update(self) -> Result<()> {
        info!("Sending update");
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_opcode(Opcode::Update);
        builder.header_mut().set_random_id();

        // Question section contains the zone
        let mut question = builder.question();
        question.push((Dname::<Vec<u8>>::from_str(&self.zone).unwrap(), Rtype::Soa))?;

        // Authority section has the updates; starting with deleting the *old* values
        let mut authority = question.authority();
        self.delete_old(&mut authority)?;
        self.push_updates(&mut authority)?;

        let mut additional = authority.additional();
        let key: tsig::Key = self.key.try_into().context("Failed to create tsig key")?;
        let mut sequence = domain::tsig::ClientSequence::request(&key, &mut additional)
            .context("Failed to sign request")?;

        let msg = additional.into_message();

        let mut servers = tokio::net::lookup_host(format!("{}:53", &self.server))
            .await
            .with_context(|| format!("Server lookup failed: {}", self.server))?;
        let addr = servers
            .next()
            .ok_or_else(|| anyhow!("No address for {}", self.server))?;

        println!("Sending update to {:?}", addr);
        let socket = match addr {
            std::net::SocketAddr::V4(_) => tokio::net::UdpSocket::bind("0.0.0.0:0").await?,
            std::net::SocketAddr::V6(_) => tokio::net::UdpSocket::bind("[::]:0").await?,
        };

        socket.connect(addr).await?;
        socket.send(msg.as_slice()).await?;
        let mut answer = loop {
            let mut buf = vec![0; 512];
            let len = socket.recv(buf.as_mut()).await?;
            buf.truncate(len);
            let answer = domain::base::Message::from_octets(buf)?;
            if answer.header().id() == msg.header().id() {
                break answer;
            }
        };

        sequence
            .answer(&mut answer)
            .context("Unexpected answer to update")?;
        sequence
            .done()
            .context("Failed to validate answer sequence")?;

        info!("Successful update");

        Ok(())
    }
}
