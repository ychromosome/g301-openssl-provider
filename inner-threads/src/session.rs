// SPDX-License-Identifier: LicenseRef-G301-Inner-Reserved

#![forbid(unsafe_code)]

use std::array;
use std::sync::OnceLock;

use openssl::cipher::{Cipher, CipherRef};

use crate::profile::{
    CanonicalApplicationContext, Channel, DerivedSecrets, HASH_LEN, IV_LEN, KEY_LEN,
    MATERIAL_COUNT, TrafficKey, derive_secrets_with_context, material_index,
};
use crate::record::{self, RecordType};
use crate::{DataChannel, EndpointRole, Error, ExporterMaterial, OpenedRecord, SessionState};

const SOFT_RECORD_LIMIT: u64 = 1 << 21;
const HARD_RECORD_LIMIT: u64 = 1 << 22;
const SOFT_BYTE_LIMIT: u64 = 1 << 35;
const HARD_BYTE_LIMIT: u64 = 1 << 36;

static AES_256_GCM: OnceLock<Result<Cipher, ()>> = OnceLock::new();

fn aes_256_gcm() -> Result<&'static CipherRef, Error> {
    match AES_256_GCM.get_or_init(|| Cipher::fetch(None, "AES-256-GCM", None).map_err(|_| ())) {
        Ok(cipher) if cipher.key_length() == KEY_LEN && cipher.iv_length() == IV_LEN => Ok(cipher),
        Ok(_) | Err(_) => Err(Error::Crypto),
    }
}

#[derive(Clone, Copy, Default)]
struct Usage {
    next_sequence: u64,
    records: u64,
    plaintext_bytes: u64,
}

impl Usage {
    fn permits(&self, plaintext_len: usize) -> bool {
        let Ok(plaintext_len) = u64::try_from(plaintext_len) else {
            return false;
        };
        self.records < HARD_RECORD_LIMIT
            && self.next_sequence < HARD_RECORD_LIMIT
            && self
                .plaintext_bytes
                .checked_add(plaintext_len)
                .is_some_and(|total| total <= HARD_BYTE_LIMIT)
    }

    fn consume(&mut self, plaintext_len: usize) -> Result<bool, Error> {
        let plaintext_len = u64::try_from(plaintext_len).map_err(|_| Error::LimitReached)?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(Error::LimitReached)?;
        self.records = self.records.checked_add(1).ok_or(Error::LimitReached)?;
        self.plaintext_bytes = self
            .plaintext_bytes
            .checked_add(plaintext_len)
            .ok_or(Error::LimitReached)?;
        Ok(self.hard_limit_reached())
    }

    const fn refresh_due(&self) -> bool {
        self.records >= SOFT_RECORD_LIMIT || self.plaintext_bytes >= SOFT_BYTE_LIMIT
    }

    const fn hard_limit_reached(&self) -> bool {
        self.next_sequence >= HARD_RECORD_LIMIT
            || self.records >= HARD_RECORD_LIMIT
            || self.plaintext_bytes >= HARD_BYTE_LIMIT
    }
}

/// A single, ordered G301 session for one endpoint.
///
/// The type intentionally exposes no keys, IVs, raw channel identifiers, or
/// arbitrary control types. All mutating operations require exclusive access,
/// serializing sequence allocation and state transitions in safe Rust.
pub struct Session {
    role: EndpointRole,
    state: SessionState,
    cipher: &'static CipherRef,
    manifest_hash: [u8; HASH_LEN],
    context_hash: [u8; HASH_LEN],
    traffic: [TrafficKey; MATERIAL_COUNT],
    usage: [Usage; MATERIAL_COUNT],
    local_commit_sent: bool,
    peer_commit_received: bool,
    local_close_sent: bool,
    peer_close_received: bool,
}

impl Session {
    /// Consumes one opaque exporter epoch and derives all ten contexts.
    ///
    /// This entry point does not itself prove TLS provenance. Normal callers
    /// cannot construct the capability from raw bytes. The future TLS adapter
    /// remains gated until it can retain the connection's private `OSSL_LIB_CTX`
    /// and consume the exporter exactly once.
    pub fn from_exporter_epoch(
        role: EndpointRole,
        exporter_material: ExporterMaterial,
        application_context: &[u8],
    ) -> Result<Self, Error> {
        let context = CanonicalApplicationContext::from_bytes(application_context)?;
        Self::from_exporter_epoch_with_context(role, exporter_material, &context)
    }

    pub(crate) fn from_exporter_epoch_with_context(
        role: EndpointRole,
        exporter_material: ExporterMaterial,
        context: &CanonicalApplicationContext,
    ) -> Result<Self, Error> {
        let DerivedSecrets {
            manifest_hash,
            context_hash,
            traffic,
        } = derive_secrets_with_context(exporter_material.as_bytes(), context)?;
        let cipher = aes_256_gcm()?;

        Ok(Self {
            role,
            state: SessionState::Committing,
            cipher,
            manifest_hash,
            context_hash,
            traffic,
            usage: array::from_fn(|_| Usage::default()),
            local_commit_sent: false,
            peer_commit_received: false,
            local_close_sent: false,
            peer_close_received: false,
        })
    }

    /// Returns the current protocol state.
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Reports whether any of the ten contexts reached a soft refresh limit.
    pub fn refresh_due(&self) -> bool {
        self.usage.iter().any(Usage::refresh_due)
    }

    /// Erases the session and makes it permanently failed.
    pub fn abort(&mut self) {
        if !matches!(self.state, SessionState::Closed | SessionState::Failed) {
            self.erase();
            self.state = SessionState::Failed;
        }
    }

    /// Produces the local endpoint's one mandatory Guard commit record.
    pub fn seal_commit(&mut self) -> Result<Vec<u8>, Error> {
        if self.state != SessionState::Committing || self.local_commit_sent {
            return self.fail(Error::InvalidState);
        }
        let output = self.seal_raw(RecordType::Commit, Channel::Guard, &[])?;
        if self.state != SessionState::Failed {
            self.local_commit_sent = true;
            if self.peer_commit_received {
                self.state = SessionState::Active;
            }
        }
        Ok(output)
    }

    /// Encrypts one application record on a typed data channel.
    pub fn seal_data(&mut self, channel: DataChannel, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.state != SessionState::Active {
            return self.fail(Error::InvalidState);
        }
        if plaintext.len() > record::MAX_PLAINTEXT {
            return self.fail(Error::PlaintextTooLarge);
        }
        self.seal_raw(RecordType::Data, channel.channel(), plaintext)
    }

    /// Signals that a fresh full TLS connection should be prepared.
    ///
    /// The old session remains active until an orderly close or a hard limit.
    pub fn seal_refresh_required(&mut self) -> Result<Vec<u8>, Error> {
        if self.state != SessionState::Active {
            return self.fail(Error::InvalidState);
        }
        self.seal_raw(RecordType::RefreshRequired, Channel::Guard, &[])
    }

    /// Initiates or acknowledges orderly shutdown.
    pub fn seal_close(&mut self) -> Result<Vec<u8>, Error> {
        let allowed = self.state == SessionState::Active
            || (self.state == SessionState::Draining && self.peer_close_received);
        if !allowed || self.local_close_sent {
            return self.fail(Error::InvalidState);
        }
        let output = self.seal_raw(RecordType::Close, Channel::Guard, &[])?;
        if self.state != SessionState::Failed {
            self.local_close_sent = true;
            self.state = SessionState::Draining;
            self.finish_close_if_complete();
        }
        Ok(output)
    }

    /// Parses, authenticates, and applies exactly one complete incoming record.
    pub fn open_record(&mut self, input: &[u8]) -> Result<OpenedRecord, Error> {
        if matches!(self.state, SessionState::Closed | SessionState::Failed) {
            return Err(Error::InvalidState);
        }
        let parsed = match record::parse(input) {
            Ok(parsed) => parsed,
            Err(error) => return self.fail(error),
        };
        if let Err(error) = self.validate_incoming(&parsed.header) {
            return self.fail(error);
        }

        let direction = self.role.receive_direction();
        let index = material_index(parsed.header.channel, direction);
        let usage = self.usage[index];
        if parsed.header.sequence != usage.next_sequence {
            return self.fail(Error::InvalidRecord);
        }
        if !usage.permits(parsed.header.plaintext_len) {
            return self.fail(Error::LimitReached);
        }

        let context = record::CryptoContext::new(
            self.cipher,
            &self.traffic[index],
            &self.manifest_hash,
            &self.context_hash,
            direction,
        );
        let plaintext = match context.open(&parsed) {
            Ok(plaintext) => plaintext,
            Err(error) => return self.fail(error),
        };
        let hard_limit_reached = match self.usage[index].consume(parsed.header.plaintext_len) {
            Ok(reached) => reached,
            Err(_) => return self.fail(Error::LimitReached),
        };

        let opened = match parsed.header.record_type {
            RecordType::Data => {
                let Some(channel) = DataChannel::from_channel(parsed.header.channel) else {
                    return self.fail(Error::InvalidRecord);
                };
                OpenedRecord::Data { channel, plaintext }
            }
            RecordType::Commit => {
                self.peer_commit_received = true;
                if self.local_commit_sent {
                    self.state = SessionState::Active;
                }
                OpenedRecord::Commit
            }
            RecordType::RefreshRequired => OpenedRecord::RefreshRequired,
            RecordType::Close => {
                self.peer_close_received = true;
                self.state = SessionState::Draining;
                self.finish_close_if_complete();
                OpenedRecord::Close
            }
        };
        self.terminate_if_hard_limit_reached(hard_limit_reached);
        Ok(opened)
    }

    fn validate_incoming(&self, header: &record::Header) -> Result<(), Error> {
        let semantically_valid = match header.record_type {
            RecordType::Data => !header.channel.is_guard(),
            RecordType::Commit | RecordType::RefreshRequired | RecordType::Close => {
                header.channel.is_guard() && header.plaintext_len == 0
            }
        };
        if !semantically_valid {
            return Err(Error::InvalidRecord);
        }

        let state_valid = match header.record_type {
            RecordType::Data | RecordType::RefreshRequired => self.state == SessionState::Active,
            RecordType::Commit => {
                self.state == SessionState::Committing && !self.peer_commit_received
            }
            RecordType::Close => {
                (self.state == SessionState::Active || self.state == SessionState::Draining)
                    && !self.peer_close_received
            }
        };
        if !state_valid {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn seal_raw(
        &mut self,
        record_type: RecordType,
        channel: Channel,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let direction = self.role.send_direction();
        let index = material_index(channel, direction);
        let usage = self.usage[index];
        if !usage.permits(plaintext.len()) {
            return self.fail(Error::LimitReached);
        }

        let context = record::CryptoContext::new(
            self.cipher,
            &self.traffic[index],
            &self.manifest_hash,
            &self.context_hash,
            direction,
        );
        let output = match context.seal(record_type, channel, usage.next_sequence, plaintext) {
            Ok(output) => output,
            Err(error) => return self.fail(error),
        };

        let hard_limit_reached = match self.usage[index].consume(plaintext.len()) {
            Ok(reached) => reached,
            Err(_) => return self.fail(Error::LimitReached),
        };
        self.terminate_if_hard_limit_reached(hard_limit_reached);
        Ok(output)
    }

    fn terminate_if_hard_limit_reached(&mut self, reached: bool) {
        if reached && !matches!(self.state, SessionState::Closed | SessionState::Failed) {
            self.erase();
            self.state = SessionState::Failed;
        }
    }

    fn finish_close_if_complete(&mut self) {
        if self.local_close_sent && self.peer_close_received {
            self.erase();
            self.state = SessionState::Closed;
        }
    }

    fn erase(&mut self) {
        for traffic in &mut self.traffic {
            traffic.erase();
        }
        self.usage.fill(Usage::default());
    }

    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        if !matches!(self.state, SessionState::Closed | SessionState::Failed) {
            self.erase();
            self.state = SessionState::Failed;
        }
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use super::*;
    use crate::profile::Direction;

    fn session() -> Session {
        Session::from_exporter_epoch(
            EndpointRole::Client,
            ExporterMaterial::for_unit_test(array::from_fn(|index| index as u8)),
            b"G301-WHITEPAPER-TEST",
        )
        .unwrap()
    }

    fn active_pair() -> (Session, Session) {
        let material = || ExporterMaterial::for_unit_test(array::from_fn(|index| index as u8));
        let mut client =
            Session::from_exporter_epoch(EndpointRole::Client, material(), b"G301-WHITEPAPER-TEST")
                .unwrap();
        let mut server =
            Session::from_exporter_epoch(EndpointRole::Server, material(), b"G301-WHITEPAPER-TEST")
                .unwrap();
        let client_commit = client.seal_commit().unwrap();
        let server_commit = server.seal_commit().unwrap();
        server.open_record(&client_commit).unwrap();
        client.open_record(&server_commit).unwrap();
        (client, server)
    }

    fn assert_erased(session: &Session) {
        assert!(session.traffic.iter().all(|traffic| {
            traffic.key.iter().all(|byte| *byte == 0) && traffic.iv.iter().all(|byte| *byte == 0)
        }));
        assert!(session.usage.iter().all(|usage| {
            usage.next_sequence == 0 && usage.records == 0 && usage.plaintext_bytes == 0
        }));
    }

    #[test]
    fn starts_in_committing() {
        assert_eq!(session().state(), SessionState::Committing);
    }

    #[test]
    fn local_state_error_is_terminal() {
        let mut session = session();
        assert!(matches!(
            session.seal_data(DataChannel::Menora, b"too early"),
            Err(Error::InvalidState)
        ));
        assert_eq!(session.state(), SessionState::Failed);
    }

    #[test]
    fn hard_limit_predicate_is_exact() {
        let mut allowed = Usage {
            next_sequence: HARD_RECORD_LIMIT - 1,
            records: HARD_RECORD_LIMIT - 1,
            plaintext_bytes: HARD_BYTE_LIMIT - 1,
        };
        assert!(allowed.permits(1));
        assert_eq!(allowed.consume(1), Ok(true));

        let exhausted = Usage {
            next_sequence: HARD_RECORD_LIMIT,
            records: HARD_RECORD_LIMIT,
            plaintext_bytes: HARD_BYTE_LIMIT,
        };
        assert!(!exhausted.permits(0));

        let mut byte_boundary = Usage {
            next_sequence: 1,
            records: 1,
            plaintext_bytes: HARD_BYTE_LIMIT - 1,
        };
        assert!(byte_boundary.permits(1));
        assert_eq!(byte_boundary.consume(1), Ok(true));
    }

    #[test]
    fn soft_limits_are_exact_and_any_context_is_reported() {
        let mut session = session();
        session.usage[0].records = SOFT_RECORD_LIMIT - 1;
        session.usage[0].plaintext_bytes = SOFT_BYTE_LIMIT - 1;
        assert!(!session.refresh_due());

        session.usage[0].records = SOFT_RECORD_LIMIT;
        assert!(session.refresh_due());
        session.usage[0].records = 0;
        session.usage[0].plaintext_bytes = SOFT_BYTE_LIMIT;
        assert!(session.refresh_due());
    }

    #[test]
    fn abort_erases_all_traffic_material_and_counters() {
        let mut session = session();
        session.usage[3] = Usage {
            next_sequence: 7,
            records: 7,
            plaintext_bytes: 301,
        };
        assert!(
            session
                .traffic
                .iter()
                .any(|traffic| traffic.key.iter().any(|byte| *byte != 0))
        );

        session.abort();
        assert_eq!(session.state(), SessionState::Failed);
        assert!(session.traffic.iter().all(|traffic| {
            traffic.key.iter().all(|byte| *byte == 0) && traffic.iv.iter().all(|byte| *byte == 0)
        }));
        assert!(session.usage.iter().all(|usage| {
            usage.next_sequence == 0 && usage.records == 0 && usage.plaintext_bytes == 0
        }));
    }

    #[test]
    fn reaching_one_context_hard_limit_terminates_both_endpoints_globally() {
        let (mut client, mut server) = active_pair();
        let index = material_index(Channel::Menora, Direction::ClientToServer);
        let immediately_before_limit = Usage {
            next_sequence: HARD_RECORD_LIMIT - 1,
            records: HARD_RECORD_LIMIT - 1,
            plaintext_bytes: 0,
        };
        client.usage[index] = immediately_before_limit;
        server.usage[index] = immediately_before_limit;

        let final_record = client.seal_data(DataChannel::Menora, b"last").unwrap();
        assert_eq!(client.state(), SessionState::Failed);
        assert_erased(&client);
        assert!(matches!(
            server.open_record(&final_record),
            Ok(OpenedRecord::Data { .. })
        ));
        assert_eq!(server.state(), SessionState::Failed);
        assert_erased(&server);

        assert_eq!(
            client.seal_data(DataChannel::Tzafah, b"sibling"),
            Err(Error::InvalidState)
        );
        assert_eq!(
            server.seal_data(DataChannel::Tzafah, b"sibling"),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn guard_close_cannot_overwrite_hard_limit_failure() {
        let (mut client, mut server) = active_pair();
        let index = material_index(Channel::Guard, Direction::ClientToServer);
        let immediately_before_limit = Usage {
            next_sequence: HARD_RECORD_LIMIT - 1,
            records: HARD_RECORD_LIMIT - 1,
            plaintext_bytes: 0,
        };
        client.usage[index] = immediately_before_limit;
        server.usage[index] = immediately_before_limit;

        let final_close = client.seal_close().unwrap();
        assert_eq!(client.state(), SessionState::Failed);
        assert_erased(&client);
        assert!(matches!(
            server.open_record(&final_close),
            Ok(OpenedRecord::Close)
        ));
        assert_eq!(server.state(), SessionState::Failed);
        assert_erased(&server);
    }

    #[test]
    fn incoming_final_close_at_hard_limit_keeps_orderly_closed_terminal() {
        let (mut client, mut server) = active_pair();
        let client_close = client.seal_close().unwrap();
        assert!(matches!(
            server.open_record(&client_close),
            Ok(OpenedRecord::Close)
        ));

        let index = material_index(Channel::Guard, Direction::ServerToClient);
        let immediately_before_limit = Usage {
            next_sequence: HARD_RECORD_LIMIT - 1,
            records: HARD_RECORD_LIMIT - 1,
            plaintext_bytes: 0,
        };
        client.usage[index] = immediately_before_limit;
        server.usage[index] = immediately_before_limit;

        let server_close = server.seal_close().unwrap();
        assert_eq!(server.state(), SessionState::Failed);
        assert_erased(&server);
        assert!(matches!(
            client.open_record(&server_close),
            Ok(OpenedRecord::Close)
        ));
        assert_eq!(client.state(), SessionState::Closed);
        assert_erased(&client);
        assert_eq!(
            client.seal_data(DataChannel::Tzafah, b"after close"),
            Err(Error::InvalidState)
        );
    }
}
