// SPDX-License-Identifier: LicenseRef-G301-Inner-Reserved

//! Experimental G301 v0.1 inner-thread session core.
//!
//! The overall project is not frozen, security-audited, standardized, release
//! ready, or approved for production use. It derives five independent channel
//! contexts in both directions (ten total) from one opaque TLS exporter value.
//!
//! The normal API deliberately exposes no raw exporter constructor. This
//! prevents production callers from accidentally creating two sessions with
//! identical AES-GCM keys and counters:
//!
//! ```compile_fail
//! use g301_inner_threads::{EndpointRole, ExporterMaterial, Session};
//!
//! let material = ExporterMaterial::new([0_u8; 48]);
//! let _ = Session::from_exporter_epoch(EndpointRole::Client, material, b"example");
//! ```
//!
//! The opaque exporter capability is also deliberately non-cloneable:
//!
//! ```compile_fail
//! use g301_inner_threads::ExporterMaterial;
//!
//! fn duplicate(material: ExporterMaterial) {
//!     let _copy = material.clone();
//! }
//! ```

#![forbid(unsafe_code)]

mod profile;
mod record;
mod session;

use std::error::Error as StdError;
use std::fmt;

use zeroize::Zeroizing;

pub use profile::EXPORTER_LABEL;
pub use session::Session;

/// Size of the TLS exporter material consumed by the G301 key schedule.
pub const EXPORTER_MATERIAL_LEN: usize = 48;

/// Whether the local endpoint is the TLS client or server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointRole {
    /// The local endpoint is the TLS client.
    Client,
    /// The local endpoint is the TLS server.
    Server,
}

impl EndpointRole {
    pub(crate) const fn send_direction(self) -> profile::Direction {
        match self {
            Self::Client => profile::Direction::ClientToServer,
            Self::Server => profile::Direction::ServerToClient,
        }
    }

    pub(crate) const fn receive_direction(self) -> profile::Direction {
        match self {
            Self::Client => profile::Direction::ServerToClient,
            Self::Server => profile::Direction::ClientToServer,
        }
    }
}

/// One of the four application-data channels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataChannel {
    /// Menora, identifier 301.
    Menora,
    /// Chanukkia, identifier 99.
    Chanukkia,
    /// Jom Kippur, identifier 372.
    JomKippur,
    /// Tzafah, identifier 175.
    Tzafah,
}

impl DataChannel {
    pub(crate) const fn channel(self) -> profile::Channel {
        match self {
            Self::Menora => profile::Channel::Menora,
            Self::Chanukkia => profile::Channel::Chanukkia,
            Self::JomKippur => profile::Channel::JomKippur,
            Self::Tzafah => profile::Channel::Tzafah,
        }
    }

    pub(crate) const fn from_channel(channel: profile::Channel) -> Option<Self> {
        match channel {
            profile::Channel::Menora => Some(Self::Menora),
            profile::Channel::Chanukkia => Some(Self::Chanukkia),
            profile::Channel::JomKippur => Some(Self::JomKippur),
            profile::Channel::Tzafah => Some(Self::Tzafah),
            profile::Channel::Guard => None,
        }
    }
}

/// The externally visible state of a G301 session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Key material has not yet entered the commit exchange.
    New,
    /// Both peers must exchange one authenticated Guard commit.
    Committing,
    /// Application data and refresh requests are allowed.
    Active,
    /// Only an outstanding close record may be exchanged.
    Draining,
    /// Both peers exchanged close records and secrets were erased.
    Closed,
    /// A cryptographic, parser, limit, or state error erased the session.
    Failed,
}

/// A successfully authenticated incoming G301 record.
pub enum OpenedRecord {
    /// Application data from one of the four data channels.
    Data {
        /// The authenticated data channel.
        channel: DataChannel,
        /// The authenticated plaintext.
        plaintext: Vec<u8>,
    },
    /// The peer's initial Guard commit.
    Commit,
    /// The peer requests preparation of a fresh full TLS connection.
    RefreshRequired,
    /// The peer initiated or acknowledged orderly shutdown.
    Close,
}

/// Exactly 48 secret bytes returned by the normal TLS exporter.
///
/// Opaque, one-shot capability containing normal TLS exporter material.
///
/// The type intentionally has no public raw-byte constructor. A future gated
/// TLS adapter must create it exactly once from a verified, completed G301
/// TLS 1.3 connection and then consume it to initialize one session.
pub struct ExporterMaterial(Zeroizing<[u8; EXPORTER_MATERIAL_LEN]>);

impl ExporterMaterial {
    #[cfg(test)]
    pub(crate) fn for_unit_test(bytes: [u8; EXPORTER_MATERIAL_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[cfg(feature = "test-vectors")]
    pub(crate) fn from_protected(bytes: Zeroizing<[u8; EXPORTER_MATERIAL_LEN]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; EXPORTER_MATERIAL_LEN] {
        &self.0
    }
}

/// Deterministic raw-exporter access for vectors, negative tests, and
/// benchmarks only.
///
/// Enabling `test-vectors` deliberately removes the production guarantee that
/// one exporter epoch can create only one session per endpoint role and
/// application context. Never enable this feature in an application build.
#[cfg(feature = "test-vectors")]
pub mod test_vectors {
    use std::mem;

    use zeroize::Zeroizing;

    use crate::{EXPORTER_MATERIAL_LEN, EndpointRole, Error, ExporterMaterial, Session};

    /// Builds a deterministic M1 session and clears the caller's source array.
    ///
    /// This function does not prove TLS provenance or freshness. It may be
    /// called repeatedly only because published vectors and benchmarks require
    /// reproducible key material.
    pub fn session_from_deterministic_exporter(
        role: EndpointRole,
        source: &mut [u8; EXPORTER_MATERIAL_LEN],
        application_context: &[u8],
    ) -> Result<Session, Error> {
        let protected = Zeroizing::new(mem::replace(source, [0; EXPORTER_MATERIAL_LEN]));
        Session::from_exporter_epoch(
            role,
            ExporterMaterial::from_protected(protected),
            application_context,
        )
    }
}

/// Stable error classes; OpenSSL internals and parser details are not exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The application context is empty or longer than 255 bytes.
    InvalidContext,
    /// The requested operation is not allowed in the current state.
    InvalidState,
    /// A record is malformed, noncanonical, or semantically invalid.
    InvalidRecord,
    /// AEAD authentication failed.
    AuthenticationFailed,
    /// A profile record or byte limit was reached.
    LimitReached,
    /// The plaintext exceeds the 16 KiB record limit.
    PlaintextTooLarge,
    /// An OpenSSL operation failed without exposing provider details.
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidContext => "invalid G301 application context",
            Self::InvalidState => "invalid G301 session state",
            Self::InvalidRecord => "invalid G301 record",
            Self::AuthenticationFailed => "G301 authentication failed",
            Self::LimitReached => "G301 key usage limit reached",
            Self::PlaintextTooLarge => "G301 plaintext exceeds 16 KiB",
            Self::Crypto => "G301 cryptographic operation failed",
        })
    }
}

impl StdError for Error {}
