//! DNS records from a local file. A valid file describes the complete record set for a PKARR packet.

use anyhow::{bail, ensure, Context, Result};
use pkarr::{
    dns::{
        rdata::SVCB,
        rdata::{RData, A, AAAA, CNAME, HTTPS, TXT},
        CharacterString, Name, ResourceRecord, CLASS,
    },
    Keypair, SignedPacket, Timestamp,
};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

const DEFAULT_TTL: u32 = 300;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordsFile {
    default_ttl: Option<u32>,
    records: Vec<Record>,
}

/// One record in the file; fields only apply to their respective record type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    ttl: Option<u32>,
    address: Option<String>,
    text: Option<String>,
    target: Option<String>,
    priority: Option<u16>,
    port: Option<u16>,
    alpn: Option<Vec<String>>,
    no_default_alpn: Option<bool>,
    ipv4hint: Option<Vec<Ipv4Addr>>,
    ipv6hint: Option<Vec<Ipv6Addr>>,
}

/// Validated, sorted records. Equality ignores file formatting and record order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecords(Vec<ResourceRecord<'static>>);

impl DnsRecords {
    /// Reads and validates the entire file. Never accepts a partial record set.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Cannot read DNS records file {path:?}"))?;
        let file: RecordsFile = toml::from_str(&contents)
            .with_context(|| format!("Invalid DNS records file {path:?}"))?;
        ensure!(
            !file.records.is_empty(),
            "DNS records file {path:?} must contain records"
        );
        let default_ttl = file.default_ttl.unwrap_or(DEFAULT_TTL);
        ensure!(
            default_ttl > 0,
            "DNS records file {path:?}: default_ttl must be positive"
        );
        let mut records = Vec::new();
        let mut cnames = HashSet::new();
        for (index, record) in file.records.into_iter().enumerate() {
            let owner = owner_name(&record.name)
                .with_context(|| format!("{path:?}: record {}", index + 1))?;
            let ttl = record.ttl.unwrap_or(default_ttl);
            ensure!(
                ttl > 0,
                "{path:?}: record {}: ttl must be positive",
                index + 1
            );
            let is_cname = record.kind == "CNAME";
            let rdata = record
                .into_rdata()
                .with_context(|| format!("{path:?}: record {}", index + 1))?;
            if is_cname {
                cnames.insert(owner.to_string());
            }
            records.push(ResourceRecord::new(owner, CLASS::IN, ttl, rdata));
        }
        for record in &records {
            if cnames.contains(&record.name.to_string()) {
                ensure!(
                    matches!(record.rdata, RData::CNAME(_))
                        && records.iter().filter(|r| r.name == record.name).count() == 1,
                    "{path:?}: CNAME cannot coexist with other records at {}",
                    record.name
                );
            }
        }
        records.sort_by_key(|record| format!("{record:?}"));
        Ok(Self(records))
    }

    /// Signs a packet with a timestamp newer than the supplied network/cache timestamp.
    pub fn sign(&self, keypair: &Keypair, previous: Option<Timestamp>) -> Result<SignedPacket> {
        let now = Timestamp::now().as_u64();
        let timestamp = previous.map_or(now, |old| now.max(old.as_u64().saturating_add(1)));
        SignedPacket::new(keypair, &self.0, Timestamp::from(timestamp.to_be_bytes()))
            .context("DNS records exceed PKARR's packet size limit or cannot be encoded")
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

fn owner_name(name: &str) -> Result<Name<'static>> {
    ensure!(
        !name.is_empty() && !name.ends_with('.'),
        "owner name must be @ or a relative DNS name"
    );
    let name = if name == "@" { "." } else { name };
    Ok(Name::new(name).context("invalid owner name")?.into_owned())
}

fn target_name(name: &str) -> Result<Name<'static>> {
    ensure!(!name.is_empty(), "target must not be empty");
    // Targets are DNS names, not owner names: '.' means the current service endpoint.
    Ok(Name::new(name).context("invalid target name")?.into_owned())
}

impl Record {
    fn into_rdata(self) -> Result<RData<'static>> {
        let service_fields = self.priority.is_some()
            || self.port.is_some()
            || self.alpn.is_some()
            || self.no_default_alpn.is_some()
            || self.ipv4hint.is_some()
            || self.ipv6hint.is_some();
        match self.kind.as_str() {
            "A" | "AAAA" | "CNAME" | "TXT" => {
                ensure!(
                    !service_fields,
                    "service parameters only apply to HTTPS/SVCB"
                );
                match self.kind.as_str() {
                    "A" => {
                        ensure!(
                            self.target.is_none() && self.text.is_none(),
                            "A accepts only address"
                        );
                        let ip: Ipv4Addr = required(self.address, "address")?
                            .parse()
                            .context("invalid IPv4 address")?;
                        Ok(RData::A(A { address: ip.into() }))
                    }
                    "AAAA" => {
                        ensure!(
                            self.target.is_none() && self.text.is_none(),
                            "AAAA accepts only address"
                        );
                        let ip: Ipv6Addr = required(self.address, "address")?
                            .parse()
                            .context("invalid IPv6 address")?;
                        Ok(RData::AAAA(AAAA { address: ip.into() }))
                    }
                    "CNAME" => {
                        ensure!(
                            self.address.is_none() && self.text.is_none(),
                            "CNAME accepts only target"
                        );
                        Ok(RData::CNAME(CNAME(target_name(&required(
                            self.target,
                            "target",
                        )?)?)))
                    }
                    _ => {
                        ensure!(
                            self.address.is_none() && self.target.is_none(),
                            "TXT accepts only text"
                        );
                        let text = required(self.text, "text")?;
                        Ok(RData::TXT(TXT::try_from(text.as_str())?.into_owned()))
                    }
                }
            }
            "HTTPS" | "SVCB" => {
                ensure!(
                    self.address.is_none() && self.text.is_none(),
                    "HTTPS/SVCB do not accept address or text"
                );
                let priority = self.priority.context("priority is required")?;
                let mut svcb = SVCB::new(priority, target_name(&required(self.target, "target")?)?);
                if priority == 0 {
                    ensure!(
                        self.port.is_none()
                            && self.alpn.is_none()
                            && self.no_default_alpn.is_none()
                            && self.ipv4hint.is_none()
                            && self.ipv6hint.is_none(),
                        "alias mode (priority 0) cannot have service parameters"
                    );
                }
                if let Some(port) = self.port {
                    ensure!(port > 0, "port must be positive");
                    svcb.set_port(port);
                }
                if let Some(ids) = self.alpn {
                    ensure!(!ids.is_empty(), "alpn must not be empty");
                    let ids: Vec<CharacterString<'static>> = ids
                        .into_iter()
                        .map(|id| {
                            ensure!(!id.is_empty(), "ALPN ID must not be empty");
                            Ok(CharacterString::try_from(id)?.into_owned())
                        })
                        .collect::<Result<_>>()?;
                    svcb.set_alpn(&ids);
                }
                if self.no_default_alpn.unwrap_or(false) {
                    ensure!(svcb.get_param(1).is_some(), "no_default_alpn requires alpn");
                    svcb.set_no_default_alpn();
                }
                if let Some(ips) = self.ipv4hint {
                    ensure!(!ips.is_empty(), "ipv4hint must not be empty");
                    svcb.set_ipv4hint(&ips.into_iter().map(u32::from).collect::<Vec<_>>());
                }
                if let Some(ips) = self.ipv6hint {
                    ensure!(!ips.is_empty(), "ipv6hint must not be empty");
                    svcb.set_ipv6hint(&ips.into_iter().map(u128::from).collect::<Vec<_>>());
                }
                if self.kind == "HTTPS" {
                    Ok(RData::HTTPS(HTTPS(svcb)))
                } else {
                    Ok(RData::SVCB(svcb))
                }
            }
            other => bail!("unsupported record type {other:?}"),
        }
    }
}

fn required(value: Option<String>, field: &str) -> Result<String> {
    value.with_context(|| format!("{field} is required"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn load(content: &str) -> Result<DnsRecords> {
        let dir = TempDir::new()?;
        let path = dir.path().join("dns-records.toml");
        fs::write(&path, content)?;
        DnsRecords::load(&path)
    }

    #[test]
    fn all_supported_types_encode_and_reordering_does_not_change_records() {
        let a = "[[records]]\nname='@'\ntype='A'\naddress='203.0.113.10'\n";
        let https = "[[records]]\nname='@'\ntype='HTTPS'\npriority=1\ntarget='.'\nport=8443\nalpn=['h2']\nipv4hint=['203.0.113.10']\n";
        let other = "[[records]]\nname='v6'\ntype='AAAA'\naddress='2001:db8::1'\n[[records]]\nname='alias'\ntype='CNAME'\ntarget='example.com.'\n[[records]]\nname='_demo'\ntype='TXT'\ntext='hello'\n[[records]]\nname='_service'\ntype='SVCB'\npriority=0\ntarget='example.com.'\n";
        let original = load(&format!("{a}{https}{other}")).unwrap();
        let reordered = load(&format!("default_ttl=300\n{other}{https}{a}")).unwrap();
        assert_eq!(original, reordered);
        let packet = original.sign(&Keypair::random(), None).unwrap();
        assert_eq!(packet.all_resource_records().count(), 6);
        let apex = packet.public_key().to_z32();
        let https = packet
            .all_resource_records()
            .find(|record| matches!(record.rdata, RData::HTTPS(_)))
            .unwrap();
        assert_eq!(https.name.to_string(), apex);
        match &https.rdata {
            RData::HTTPS(HTTPS(svcb)) => {
                assert_eq!(svcb.priority, 1);
                assert_eq!(
                    svcb.get_param(3),
                    Some(&pkarr::dns::rdata::SVCParam::Port(8443))
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn invalid_files_are_never_partially_accepted() {
        for input in [
            "records=[]",
            "[[records]]\nname='@'\ntype='A'\naddress='not-an-ip'",
            "[[records]]\nname='@'\ntype='HTTPS'\npriority=0\ntarget='.'\nport=443",
            "[[records]]\nname='@'\ntype='A'\naddress='127.0.0.1'\nport=443",
            "[[records]]\nname='@'\ntype='TXT'\ntext='x'\nunknown=1",
            "[[records]]\nname='foo'\ntype='CNAME'\ntarget='example.com.'\n[[records]]\nname='foo'\ntype='A'\naddress='127.0.0.1'",
        ] {
            assert!(load(input).is_err(), "unexpectedly accepted: {input}");
        }
    }

    #[test]
    fn oversized_packets_fail_before_publication() {
        let text = (0..8)
            .map(|i| {
                format!(
                    "[[records]]\nname='t{i}'\ntype='TXT'\ntext='{}'\n",
                    "x".repeat(200)
                )
            })
            .collect::<String>();
        let records = load(&text).unwrap();
        assert!(records.sign(&Keypair::random(), None).is_err());
    }
}
