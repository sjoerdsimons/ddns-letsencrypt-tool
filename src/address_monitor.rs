// opens a netlink socket and listens for connection status and address changes
// for each network interface

use futures::stream::StreamExt;
use futures::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_core::NetlinkPayload;

use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::address::AddressScope;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::link::State;
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    constants::{RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK},
    new_connection,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum ListenError {
    #[error("IO error")]
    IoError(#[from] std::io::Error),
    #[error("RtNetlinkError")]
    RtNetlinkError(#[from] rtnetlink::Error),
    #[error("Netlink error: {code:?}")]
    NetlinkError { code: i32 },
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Address {
    pub ip: IpNetwork,
    pub interface: u32,
    //pub flags: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct LinkInfo {
    addrs: HashSet<Address>,
    state: State,
    flags: LinkFlags,
    ifname: String,
}

impl LinkInfo {
    fn new(ifname: &str, state: State, flags: LinkFlags) -> Self {
        LinkInfo {
            addrs: HashSet::new(),
            state,
            flags,
            ifname: ifname.to_string(),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct Link {
    index: u32,
}

pub struct AddressMonitor {
    links: HashMap<Link, LinkInfo>,
    messages: futures::channel::mpsc::UnboundedReceiver<(
        NetlinkMessage<RouteNetlinkMessage>,
        SocketAddr,
    )>,
}

impl AddressMonitor {
    pub async fn new() -> anyhow::Result<Self> {
        let (mut connection, handle, messages) = new_connection()?;

        // create netlink socket
        let groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
        let link_socket = SocketAddr::new(0, groups);

        // bind and listen
        connection.socket_mut().socket_mut().bind(&link_socket)?;
        tokio::spawn(connection);
        let mut this = Self {
            links: HashMap::new(),
            messages,
        };

        // dump the current links
        let mut links = handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            this.handle_new_link(&link).await;
        }

        // dump the current addresses
        let mut addrs = handle.address().get().execute();
        while let Some(addr) = addrs.try_next().await? {
            this.handle_add_addr(&addr).await;
        }
        Ok(this)
    }

    pub fn iter_addresses(&self) -> impl Iterator<Item = &Address> {
        self.links
            .values()
            .filter_map(|info| {
                let is_up = info.state == State::Up
                    || (info.state == State::Unknown && info.flags.contains(LinkFlags::Running));
                if is_up { Some(info.addrs.iter()) } else { None }
            })
            .flatten()
    }

    fn parse_link_message(msg: &LinkMessage) -> Option<(Link, &str, State, LinkFlags)> {
        if msg.header.flags.contains(LinkFlags::Loopback) {
            return None;
        }
        let link = Link {
            index: msg.header.index,
        };
        let flags = msg.header.flags;
        let mut ifname: Option<&str> = None;
        let mut state: Option<State> = None;

        for nla in &msg.attributes {
            match nla {
                LinkAttribute::IfName(i) => ifname = Some(i),
                LinkAttribute::OperState(s) => state = Some(*s),
                _ => (),
            }
        }
        if let (Some(ifname), Some(state)) = (ifname, state) {
            Some((link, ifname, state, flags))
        } else {
            warn!(
                "Couldn't parse message, either ifname or state missing) msg={:?}",
                msg
            );
            None
        }
    }

    async fn handle_new_link(&mut self, msg: &LinkMessage) {
        if let Some((link, ifname, state, flags)) = Self::parse_link_message(msg) {
            if let Some(info) = self.links.get_mut(&link) {
                if info.state != state || info.flags != flags {
                    info.state = state;
                    info.flags = flags;
                    info!("{} ({})  state changed to {:?}", ifname, link.index, state);
                }
            } else {
                info!("Link {} ({}) added, state {:?}", ifname, link.index, state);
                self.links.insert(link, LinkInfo::new(ifname, state, flags));
            }
        }
    }

    async fn handle_del_link(&mut self, msg: &LinkMessage) {
        if let Some((link, ifname, _, _)) = Self::parse_link_message(msg)
            && let Some(_info) = self.links.remove(&link)
        {
            info!("Link {} ({}) removed", ifname, link.index);
        }
    }

    fn parse_address_message(msg: &AddressMessage) -> Option<(Link, Address)> {
        if msg.header.scope != AddressScope::Universe {
            return None;
        }

        let link = Link {
            index: msg.header.index,
        };

        let mut local_ip: Option<&IpAddr> = None;
        let mut addr_ip: Option<&IpAddr> = None;
        for a in &msg.attributes {
            match a {
                AddressAttribute::Local(ip) => local_ip = Some(ip),
                AddressAttribute::Address(ip) => addr_ip = Some(ip),
                _ => (),
            }
        }
        // For point-to-point links (e.g. ppp0), IFA_LOCAL is the local address
        // while IFA_ADDRESS is the remote peer's address. Prefer Local over Address.
        let ip = local_ip.or(addr_ip);

        if let Some(ip) = ip {
            let ip = IpNetwork::new(*ip, msg.header.prefix_len).ok()?;
            let address = Address {
                ip,
                interface: link.index,
            };
            Some((link, address))
        } else {
            None
        }
    }

    async fn handle_add_addr(&mut self, msg: &AddressMessage) {
        if let Some((link, address)) = Self::parse_address_message(msg) {
            if let Some(info) = self.links.get_mut(&link) {
                if info.addrs.contains(&address) {
                    debug!("Ignoring duplicate address!: {:?}, {:?}", info, address);
                } else {
                    info!(
                        "Link {} ({}) added address {}",
                        info.ifname, link.index, address.ip
                    );
                    info.addrs.insert(address);
                }
            } else {
                warn!("Address added for unknown link!: {:?}, {:?}", link, address);
            }
        }
    }

    async fn handle_rm_addr(&mut self, msg: &AddressMessage) {
        if let Some((link, address)) = Self::parse_address_message(msg) {
            if let Some(info) = self.links.get_mut(&link) {
                if info.addrs.remove(&address) {
                    info!(
                        "Link {} ({}) removed address {}",
                        info.ifname, link.index, address.ip
                    );
                }
            } else {
                warn!(
                    "Address removed for unknown link!: {:?}, {:?}",
                    link, address
                );
            }
        }
    }

    pub async fn wait_for_event(&mut self) -> Result<(), ListenError> {
        // handle link changes
        if let Some((msg, _)) = self.messages.next().await {
            match msg.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
                    self.handle_new_link(&link).await;
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) => {
                    self.handle_del_link(&link).await;
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr)) => {
                    self.handle_add_addr(&addr).await;
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(addr)) => {
                    self.handle_rm_addr(&addr).await;
                }
                NetlinkPayload::Error(err) => {
                    return Err(ListenError::NetlinkError {
                        code: err.raw_code(),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}
