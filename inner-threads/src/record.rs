// SPDX-License-Identifier: LicenseRef-G301-Inner-Reserved

#![forbid(unsafe_code)]

use openssl::cipher::CipherRef;
use openssl::cipher_ctx::{CipherCtx, CipherCtxRef};
use zeroize::Zeroize;

use crate::Error;
use crate::profile::{Channel, Direction, HASH_LEN, IV_LEN, KEY_LEN, SUITE, TrafficKey};

pub(crate) const VERSION: u8 = 1;
pub(crate) const HEADER_LEN: usize = 16;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const MAX_PLAINTEXT: usize = 1 << 14;
const AAD_LEN: usize = 2 + SUITE.len() + (2 * HASH_LEN) + 1 + HEADER_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum RecordType {
    Data = 0x00,
    Commit = 0x80,
    RefreshRequired = 0x81,
    Close = 0x82,
}

impl RecordType {
    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Data),
            0x80 => Some(Self::Commit),
            0x81 => Some(Self::RefreshRequired),
            0x82 => Some(Self::Close),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Header {
    pub(crate) record_type: RecordType,
    pub(crate) channel: Channel,
    pub(crate) sequence: u64,
    pub(crate) plaintext_len: usize,
    encoded: [u8; HEADER_LEN],
}

impl Header {
    pub(crate) fn new(
        record_type: RecordType,
        channel: Channel,
        sequence: u64,
        plaintext_len: usize,
    ) -> Result<Self, Error> {
        if plaintext_len > MAX_PLAINTEXT {
            return Err(Error::PlaintextTooLarge);
        }
        let plaintext_len_u32 =
            u32::try_from(plaintext_len).map_err(|_| Error::PlaintextTooLarge)?;
        let mut encoded = [0; HEADER_LEN];
        encoded[0] = VERSION;
        encoded[1] = record_type as u8;
        encoded[2..4].copy_from_slice(&channel.id().to_be_bytes());
        encoded[4..12].copy_from_slice(&sequence.to_be_bytes());
        encoded[12..16].copy_from_slice(&plaintext_len_u32.to_be_bytes());
        Ok(Self {
            record_type,
            channel,
            sequence,
            plaintext_len,
            encoded,
        })
    }

    pub(crate) const fn encoded(&self) -> &[u8; HEADER_LEN] {
        &self.encoded
    }

    fn decode(encoded: [u8; HEADER_LEN]) -> Result<Self, Error> {
        if encoded[0] != VERSION {
            return Err(Error::InvalidRecord);
        }
        let record_type = RecordType::from_byte(encoded[1]).ok_or(Error::InvalidRecord)?;
        let channel_id =
            u16::from_be_bytes(encoded[2..4].try_into().map_err(|_| Error::InvalidRecord)?);
        let channel = Channel::from_id(channel_id).ok_or(Error::InvalidRecord)?;
        let sequence = u64::from_be_bytes(
            encoded[4..12]
                .try_into()
                .map_err(|_| Error::InvalidRecord)?,
        );
        let plaintext_len = u32::from_be_bytes(
            encoded[12..16]
                .try_into()
                .map_err(|_| Error::InvalidRecord)?,
        ) as usize;
        if plaintext_len > MAX_PLAINTEXT {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            record_type,
            channel,
            sequence,
            plaintext_len,
            encoded,
        })
    }

    fn expected_wire_len(&self) -> Result<usize, Error> {
        HEADER_LEN
            .checked_add(self.plaintext_len)
            .and_then(|value| value.checked_add(TAG_LEN))
            .ok_or(Error::InvalidRecord)
    }
}

pub(crate) struct ParsedRecord<'a> {
    pub(crate) header: Header,
    pub(crate) ciphertext: &'a [u8],
    pub(crate) tag: &'a [u8; TAG_LEN],
}

pub(crate) struct CryptoContext<'a> {
    cipher: &'a CipherRef,
    traffic: &'a TrafficKey,
    manifest_hash: &'a [u8; HASH_LEN],
    context_hash: &'a [u8; HASH_LEN],
    direction: Direction,
}

impl<'a> CryptoContext<'a> {
    pub(crate) const fn new(
        cipher: &'a CipherRef,
        traffic: &'a TrafficKey,
        manifest_hash: &'a [u8; HASH_LEN],
        context_hash: &'a [u8; HASH_LEN],
        direction: Direction,
    ) -> Self {
        Self {
            cipher,
            traffic,
            manifest_hash,
            context_hash,
            direction,
        }
    }

    pub(crate) fn seal(
        &self,
        record_type: RecordType,
        channel: Channel,
        sequence: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let header = Header::new(record_type, channel, sequence, plaintext.len())?;
        let aad = aad(
            self.manifest_hash,
            self.context_hash,
            self.direction,
            header.encoded(),
        );
        let nonce = nonce(&self.traffic.iv, sequence);
        let mut ctx = init_encrypt(self.cipher, &self.traffic.key, &nonce)?;
        update_aad(&mut ctx, &aad)?;

        let mut output = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
        output.extend_from_slice(header.encoded());
        let written = ctx
            .cipher_update_vec(plaintext, &mut output)
            .map_err(|_| Error::Crypto)?;
        if written != plaintext.len() {
            return Err(Error::Crypto);
        }
        let final_written = ctx
            .cipher_final_vec(&mut output)
            .map_err(|_| Error::Crypto)?;
        if final_written != 0 || output.len() != HEADER_LEN + plaintext.len() {
            return Err(Error::Crypto);
        }
        let mut tag = [0; TAG_LEN];
        ctx.tag(&mut tag).map_err(|_| Error::Crypto)?;
        output.extend_from_slice(&tag);
        Ok(output)
    }

    pub(crate) fn open(&self, parsed: &ParsedRecord<'_>) -> Result<Vec<u8>, Error> {
        let aad = aad(
            self.manifest_hash,
            self.context_hash,
            self.direction,
            parsed.header.encoded(),
        );
        let nonce = nonce(&self.traffic.iv, parsed.header.sequence);
        let mut plaintext = Vec::with_capacity(parsed.header.plaintext_len);

        let result = (|| {
            let mut ctx = init_decrypt(self.cipher, &self.traffic.key, &nonce)?;
            update_aad(&mut ctx, &aad)?;
            let written = ctx
                .cipher_update_vec(parsed.ciphertext, &mut plaintext)
                .map_err(|_| Error::AuthenticationFailed)?;
            if written != parsed.header.plaintext_len {
                return Err(Error::AuthenticationFailed);
            }
            ctx.set_tag(parsed.tag)
                .map_err(|_| Error::AuthenticationFailed)?;
            let final_written = ctx
                .cipher_final_vec(&mut plaintext)
                .map_err(|_| Error::AuthenticationFailed)?;
            if final_written != 0 || plaintext.len() != parsed.header.plaintext_len {
                return Err(Error::AuthenticationFailed);
            }
            Ok(())
        })();

        if let Err(error) = result {
            plaintext.zeroize();
            return Err(error);
        }
        Ok(plaintext)
    }
}

pub(crate) fn parse(input: &[u8]) -> Result<ParsedRecord<'_>, Error> {
    if input.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::InvalidRecord);
    }
    let encoded = input[..HEADER_LEN]
        .try_into()
        .map_err(|_| Error::InvalidRecord)?;
    let header = Header::decode(encoded)?;
    let expected_len = header.expected_wire_len()?;
    if input.len() != expected_len {
        return Err(Error::InvalidRecord);
    }

    let ciphertext = &input[HEADER_LEN..HEADER_LEN + header.plaintext_len];
    let tag = (&input[HEADER_LEN + header.plaintext_len..])
        .try_into()
        .map_err(|_| Error::InvalidRecord)?;
    Ok(ParsedRecord {
        header,
        ciphertext,
        tag,
    })
}

fn aad(
    manifest_hash: &[u8; HASH_LEN],
    context_hash: &[u8; HASH_LEN],
    direction: Direction,
    header: &[u8; HEADER_LEN],
) -> [u8; AAD_LEN] {
    let mut aad = [0; AAD_LEN];
    let mut offset = 0;
    for part in [
        &(SUITE.len() as u16).to_be_bytes()[..],
        SUITE,
        &manifest_hash[..],
        &context_hash[..],
        &[direction as u8],
        &header[..],
    ] {
        aad[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    debug_assert_eq!(offset, AAD_LEN);
    aad
}

fn nonce(iv: &[u8; IV_LEN], sequence: u64) -> [u8; IV_LEN] {
    let mut out = *iv;
    let encoded = sequence.to_be_bytes();
    for (dst, src) in out[4..].iter_mut().zip(encoded) {
        *dst ^= src;
    }
    out
}

fn init_encrypt(
    cipher: &CipherRef,
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
) -> Result<CipherCtx, Error> {
    let mut ctx = CipherCtx::new().map_err(|_| Error::Crypto)?;
    ctx.encrypt_init(Some(cipher), None, None)
        .map_err(|_| Error::Crypto)?;
    ctx.set_iv_length(IV_LEN).map_err(|_| Error::Crypto)?;
    ctx.encrypt_init(None, Some(key), Some(iv))
        .map_err(|_| Error::Crypto)?;
    Ok(ctx)
}

fn init_decrypt(
    cipher: &CipherRef,
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
) -> Result<CipherCtx, Error> {
    let mut ctx = CipherCtx::new().map_err(|_| Error::Crypto)?;
    ctx.decrypt_init(Some(cipher), None, None)
        .map_err(|_| Error::Crypto)?;
    ctx.set_iv_length(IV_LEN).map_err(|_| Error::Crypto)?;
    ctx.decrypt_init(None, Some(key), Some(iv))
        .map_err(|_| Error::Crypto)?;
    Ok(ctx)
}

fn update_aad(ctx: &mut CipherCtxRef, value: &[u8]) -> Result<(), Error> {
    ctx.cipher_update(value, None).map_err(|_| Error::Crypto)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::array;

    use openssl::cipher::Cipher;

    use super::*;
    use crate::profile::{derive_secrets, material_index};

    fn bytes(value: &str) -> Vec<u8> {
        hex::decode(value).unwrap()
    }

    fn mock_ekm() -> [u8; 48] {
        array::from_fn(|index| index as u8)
    }

    #[test]
    fn whitepaper_records_match() {
        let secrets = derive_secrets(&mock_ekm(), b"G301-WHITEPAPER-TEST").unwrap();
        let cipher = Cipher::fetch(None, "AES-256-GCM", None).unwrap();
        let menora = &secrets.traffic[material_index(Channel::Menora, Direction::ClientToServer)];

        let menora_context = CryptoContext::new(
            &cipher,
            menora,
            &secrets.manifest_hash,
            &secrets.context_hash,
            Direction::ClientToServer,
        );
        let sequence_zero = menora_context
            .seal(RecordType::Data, Channel::Menora, 0, b"G301")
            .unwrap();
        assert_eq!(
            sequence_zero,
            bytes("0100012d000000000000000000000004c130c2b21e8546f0c615ffecfe919005e67675c9")
        );

        let sequence_one = menora_context
            .seal(RecordType::Data, Channel::Menora, 1, b"G301")
            .unwrap();
        assert_eq!(
            sequence_one,
            bytes("0100012d0000000000000001000000046dd57b7324a1dc8ff031d88f5a39717a85cd0cd3")
        );

        let guard = &secrets.traffic[material_index(Channel::Guard, Direction::ClientToServer)];
        let guard_context = CryptoContext::new(
            &cipher,
            guard,
            &secrets.manifest_hash,
            &secrets.context_hash,
            Direction::ClientToServer,
        );
        let commit = guard_context
            .seal(RecordType::Commit, Channel::Guard, 0, b"")
            .unwrap();
        assert_eq!(
            commit,
            bytes("018003b3000000000000000000000000c33c525be4b6d17346772275e14cb1c0")
        );
    }

    #[test]
    fn nonce_and_aad_framing_are_exact() {
        let iv: [u8; IV_LEN] = hex::decode("3f3bc8cfde490a24c9f00a90")
            .unwrap()
            .try_into()
            .unwrap();
        let expected_nonce: [u8; IV_LEN] = hex::decode("3f3bc8cfde490a24c9f00a91")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(nonce(&iv, 1), expected_nonce);
        assert_eq!(nonce(&iv, 0), iv);

        let secrets = derive_secrets(&mock_ekm(), b"G301-WHITEPAPER-TEST").unwrap();
        let header = Header::new(RecordType::Data, Channel::Menora, 1, 4).unwrap();
        let framed = aad(
            &secrets.manifest_hash,
            &secrets.context_hash,
            Direction::ClientToServer,
            header.encoded(),
        );
        let suite_end = 2 + SUITE.len();
        assert_eq!(&framed[..2], &(SUITE.len() as u16).to_be_bytes());
        assert_eq!(&framed[2..suite_end], SUITE);
        assert_eq!(
            &framed[suite_end..suite_end + HASH_LEN],
            &secrets.manifest_hash
        );
        assert_eq!(framed[suite_end + 2 * HASH_LEN], 0);
        assert_eq!(&framed[AAD_LEN - HEADER_LEN..], header.encoded());
    }
}
