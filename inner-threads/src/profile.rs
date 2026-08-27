// SPDX-License-Identifier: LicenseRef-G301-Inner-Reserved

#![forbid(unsafe_code)]

use std::array;

use openssl::hash::{MessageDigest, hash};
use openssl::kdf::{HkdfMode, hkdf};
use openssl::md::Md;
use zeroize::{Zeroize, Zeroizing};

use crate::{EXPORTER_MATERIAL_LEN, Error};

pub(crate) const SUITE: &[u8] = b"G301-ORLOGTHATTR-AEAD-v1";
/// TLS exporter label reserved by the G301 draft profile.
pub const EXPORTER_LABEL: &str = "EXPERIMENTAL-G301-ORLOGTHATTR-AEAD-v1";
pub(crate) const HASH_LEN: usize = 48;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const IV_LEN: usize = 12;
pub(crate) const MATERIAL_COUNT: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Direction {
    ClientToServer = 0,
    ServerToClient = 1,
}

impl Direction {
    const ALL: [Self; 2] = [Self::ClientToServer, Self::ServerToClient];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Channel {
    Menora,
    Chanukkia,
    JomKippur,
    Tzafah,
    Guard,
}

impl Channel {
    pub(crate) const ALL: [Self; 5] = [
        Self::Menora,
        Self::Chanukkia,
        Self::JomKippur,
        Self::Tzafah,
        Self::Guard,
    ];

    pub(crate) const fn id(self) -> u16 {
        match self {
            Self::Menora => 301,
            Self::Chanukkia => 99,
            Self::JomKippur => 372,
            Self::Tzafah => 175,
            Self::Guard => 947,
        }
    }

    const fn role(self) -> u8 {
        match self {
            Self::Guard => 1,
            _ => 0,
        }
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::Menora => b"MENORA",
            Self::Chanukkia => b"CHANUKKIA",
            Self::JomKippur => b"JOM-KIPPUR",
            Self::Tzafah => b"TZAFAH",
            Self::Guard => b"GUARD",
        }
    }

    pub(crate) const fn is_guard(self) -> bool {
        matches!(self, Self::Guard)
    }

    pub(crate) const fn from_id(id: u16) -> Option<Self> {
        match id {
            301 => Some(Self::Menora),
            99 => Some(Self::Chanukkia),
            372 => Some(Self::JomKippur),
            175 => Some(Self::Tzafah),
            947 => Some(Self::Guard),
            _ => None,
        }
    }

    const fn ordinal(self) -> usize {
        match self {
            Self::Menora => 0,
            Self::Chanukkia => 1,
            Self::JomKippur => 2,
            Self::Tzafah => 3,
            Self::Guard => 4,
        }
    }
}

pub(crate) const fn material_index(channel: Channel, direction: Direction) -> usize {
    channel.ordinal() * 2 + direction as usize
}

pub(crate) struct TrafficKey {
    pub(crate) key: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) iv: Zeroizing<[u8; IV_LEN]>,
}

impl TrafficKey {
    fn zeroed() -> Self {
        Self {
            key: Zeroizing::new([0; KEY_LEN]),
            iv: Zeroizing::new([0; IV_LEN]),
        }
    }

    pub(crate) fn erase(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

pub(crate) struct DerivedSecrets {
    pub(crate) manifest_hash: [u8; HASH_LEN],
    pub(crate) context_hash: [u8; HASH_LEN],
    pub(crate) traffic: [TrafficKey; MATERIAL_COUNT],
}

/// The single canonical M1 context calculation shared by the TLS exporter
/// and the session key schedule.
pub(crate) struct CanonicalApplicationContext {
    manifest_hash: [u8; HASH_LEN],
    context_hash: [u8; HASH_LEN],
}

impl CanonicalApplicationContext {
    pub(crate) fn from_bytes(application_context: &[u8]) -> Result<Self, Error> {
        if application_context.is_empty() || application_context.len() > u8::MAX as usize {
            return Err(Error::InvalidContext);
        }
        let manifest_hash = manifest_hash()?;
        let context_hash = build_context_hash(&manifest_hash, application_context)?;
        Ok(Self {
            manifest_hash,
            context_hash,
        })
    }

    pub(crate) const fn exporter_context(&self) -> &[u8; HASH_LEN] {
        &self.context_hash
    }
}

/// Returns the one canonical 48-byte v0.1 manifest hash used by the
/// application-context wrapper and session key schedule.
pub(crate) fn manifest_hash() -> Result<[u8; HASH_LEN], Error> {
    sha384(&manifest()?)
}

struct RootDerivation {
    manifest_hash: [u8; HASH_LEN],
    context_hash: [u8; HASH_LEN],
    prk: Zeroizing<[u8; HASH_LEN]>,
}

fn append_be16(out: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    let value = u16::try_from(value).map_err(|_| Error::InvalidContext)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn append_lp8(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    let len = u8::try_from(value.len()).map_err(|_| Error::InvalidContext)?;
    out.push(len);
    out.extend_from_slice(value);
    Ok(())
}

fn append_lp16(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    append_be16(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

pub(crate) fn manifest() -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(83);
    append_lp16(&mut out, SUITE)?;
    out.push(Channel::ALL.len() as u8);
    for channel in Channel::ALL {
        out.push(channel.role());
        out.extend_from_slice(&channel.id().to_be_bytes());
        append_lp8(&mut out, channel.label())?;
    }
    Ok(out)
}

fn sha384(input: &[u8]) -> Result<[u8; HASH_LEN], Error> {
    let digest = hash(MessageDigest::sha384(), input).map_err(|_| Error::Crypto)?;
    let mut out = [0; HASH_LEN];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn build_context_hash(
    manifest_hash: &[u8; HASH_LEN],
    application_context: &[u8],
) -> Result<[u8; HASH_LEN], Error> {
    let mut framed = Vec::with_capacity(2 + SUITE.len() + HASH_LEN + 2 + 255);
    append_lp16(&mut framed, SUITE)?;
    framed.extend_from_slice(manifest_hash);
    append_lp16(&mut framed, application_context)?;
    sha384(&framed)
}

fn build_salt(
    manifest_hash: &[u8; HASH_LEN],
    context_hash: &[u8; HASH_LEN],
) -> Result<[u8; HASH_LEN], Error> {
    let mut framed = Vec::with_capacity(2 + SUITE.len() + 2 * HASH_LEN);
    append_lp16(&mut framed, SUITE)?;
    framed.extend_from_slice(manifest_hash);
    framed.extend_from_slice(context_hash);
    sha384(&framed)
}

fn build_info(
    purpose: &[u8],
    manifest_hash: &[u8; HASH_LEN],
    context_hash: &[u8; HASH_LEN],
    channel: Channel,
    direction: Direction,
) -> Result<Vec<u8>, Error> {
    let mut info = Vec::with_capacity(2 + SUITE.len() + 1 + purpose.len() + 2 * HASH_LEN + 4);
    append_lp16(&mut info, SUITE)?;
    append_lp8(&mut info, purpose)?;
    info.extend_from_slice(manifest_hash);
    info.extend_from_slice(context_hash);
    info.extend_from_slice(&channel.id().to_be_bytes());
    info.push(channel.role());
    info.push(direction as u8);
    Ok(info)
}

#[cfg(test)]
fn derive_root(
    exporter_material: &[u8; EXPORTER_MATERIAL_LEN],
    application_context: &[u8],
) -> Result<RootDerivation, Error> {
    let context = CanonicalApplicationContext::from_bytes(application_context)?;
    derive_root_with_context(exporter_material, &context)
}

fn derive_root_with_context(
    exporter_material: &[u8; EXPORTER_MATERIAL_LEN],
    context: &CanonicalApplicationContext,
) -> Result<RootDerivation, Error> {
    let manifest_hash = context.manifest_hash;
    let context_hash = *context.exporter_context();
    let salt = build_salt(&manifest_hash, &context_hash)?;
    let mut prk = Zeroizing::new([0; HASH_LEN]);
    hkdf(
        Md::sha384(),
        exporter_material,
        Some(&salt),
        None,
        HkdfMode::ExtractOnly,
        None,
        &mut *prk,
    )
    .map_err(|_| Error::Crypto)?;
    Ok(RootDerivation {
        manifest_hash,
        context_hash,
        prk,
    })
}

#[cfg(test)]
pub(crate) fn derive_secrets(
    exporter_material: &[u8; EXPORTER_MATERIAL_LEN],
    application_context: &[u8],
) -> Result<DerivedSecrets, Error> {
    let context = CanonicalApplicationContext::from_bytes(application_context)?;
    derive_secrets_with_context(exporter_material, &context)
}

pub(crate) fn derive_secrets_with_context(
    exporter_material: &[u8; EXPORTER_MATERIAL_LEN],
    context: &CanonicalApplicationContext,
) -> Result<DerivedSecrets, Error> {
    let RootDerivation {
        manifest_hash,
        context_hash,
        prk,
    } = derive_root_with_context(exporter_material, context)?;
    let mut traffic: [TrafficKey; MATERIAL_COUNT] = array::from_fn(|_| TrafficKey::zeroed());

    for channel in Channel::ALL {
        for direction in Direction::ALL {
            let index = material_index(channel, direction);
            let mut traffic_secret = Zeroizing::new([0; HASH_LEN]);
            let traffic_info = build_info(
                b"traffic",
                &manifest_hash,
                &context_hash,
                channel,
                direction,
            )?;
            hkdf(
                Md::sha384(),
                &*prk,
                None,
                Some(&traffic_info),
                HkdfMode::ExpandOnly,
                None,
                &mut *traffic_secret,
            )
            .map_err(|_| Error::Crypto)?;

            let key_info = build_info(b"key", &manifest_hash, &context_hash, channel, direction)?;
            hkdf(
                Md::sha384(),
                &*traffic_secret,
                None,
                Some(&key_info),
                HkdfMode::ExpandOnly,
                None,
                &mut *traffic[index].key,
            )
            .map_err(|_| Error::Crypto)?;

            let iv_info = build_info(b"iv", &manifest_hash, &context_hash, channel, direction)?;
            hkdf(
                Md::sha384(),
                &*traffic_secret,
                None,
                Some(&iv_info),
                HkdfMode::ExpandOnly,
                None,
                &mut *traffic[index].iv,
            )
            .map_err(|_| Error::Crypto)?;
        }
    }

    Ok(DerivedSecrets {
        manifest_hash,
        context_hash,
        traffic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn mock_ekm() -> [u8; EXPORTER_MATERIAL_LEN] {
        array::from_fn(|index| index as u8)
    }

    #[test]
    fn whitepaper_manifest_and_key_schedule_match() {
        assert_eq!(
            manifest(),
            Ok(hex::decode(
                "0018473330312d4f524c4f475448415454522d414541442d76310500012d064d454e4f5241000063094348414e554b4b49410001740a4a4f4d2d4b49505055520000af06545a414641480103b3054755415244"
            )
            .unwrap())
        );

        let RootDerivation {
            manifest_hash,
            context_hash,
            prk,
        } = derive_root(&mock_ekm(), b"G301-WHITEPAPER-TEST").unwrap();
        assert_eq!(
            manifest_hash,
            bytes(
                "44a3c009427ff37bb751b3165c01ce6242506dd59655ccab30f26075de9b84fd9e0d8fb42715b18f534bedfbcdd37e0e"
            )
        );
        assert_eq!(
            context_hash,
            bytes(
                "5cc3ad0b332f266abd9e278845a6fdccd386883e1d713003781bc4466a796996f708248ab1b83fcb6ecf4b55c4cb2273"
            )
        );
        assert_eq!(
            *prk,
            bytes(
                "ce978992ca7bb97dac1851557103a0e5c5aa1740b2de0277897679f05887d4299b0dd40ade44449725dd353f91878624"
            )
        );

        let secrets = derive_secrets(&mock_ekm(), b"G301-WHITEPAPER-TEST").unwrap();
        let index = material_index(Channel::Menora, Direction::ClientToServer);
        assert_eq!(
            *secrets.traffic[index].key,
            bytes("8f8a4133c88f9d3d19c0a55deba7c198ee6b0fea93fee0a5be1bc364d9a4d821")
        );
        assert_eq!(
            *secrets.traffic[index].iv,
            bytes("3f3bc8cfde490a24c9f00a90")
        );
    }

    #[test]
    fn all_channel_direction_material_is_distinct_and_indexed_once() {
        let secrets = derive_secrets(&mock_ekm(), b"G301-WHITEPAPER-TEST").unwrap();
        let mut seen_indices = [false; MATERIAL_COUNT];

        for channel in Channel::ALL {
            for direction in Direction::ALL {
                let index = material_index(channel, direction);
                assert!(!seen_indices[index]);
                seen_indices[index] = true;
            }
        }
        assert!(seen_indices.into_iter().all(|seen| seen));

        for left in 0..MATERIAL_COUNT {
            for right in left + 1..MATERIAL_COUNT {
                assert_ne!(*secrets.traffic[left].key, *secrets.traffic[right].key);
                assert_ne!(*secrets.traffic[left].iv, *secrets.traffic[right].iv);
            }
        }
    }
}
