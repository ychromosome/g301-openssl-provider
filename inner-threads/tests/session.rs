// SPDX-License-Identifier: LicenseRef-G301-Inner-Reserved

use std::array;

use g301_inner_threads::test_vectors::session_from_deterministic_exporter;
use g301_inner_threads::{DataChannel, EndpointRole, Error, OpenedRecord, Session, SessionState};

const CONTEXT: &[u8] = b"G301-WHITEPAPER-TEST";

fn exporter_bytes() -> [u8; 48] {
    array::from_fn(|index| index as u8)
}

fn construct(role: EndpointRole, mut exporter: [u8; 48], context: &[u8]) -> Result<Session, Error> {
    let result = session_from_deterministic_exporter(role, &mut exporter, context);
    assert_eq!(exporter, [0; 48]);
    result
}

fn pair() -> (Session, Session) {
    let client = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    let server = construct(EndpointRole::Server, exporter_bytes(), CONTEXT).unwrap();
    (client, server)
}

fn active_pair() -> (Session, Session) {
    let (mut client, mut server) = pair();
    let client_commit = client.seal_commit().unwrap();
    let server_commit = server.seal_commit().unwrap();
    assert!(matches!(
        server.open_record(&client_commit),
        Ok(OpenedRecord::Commit)
    ));
    assert!(matches!(
        client.open_record(&server_commit),
        Ok(OpenedRecord::Commit)
    ));
    assert_eq!(client.state(), SessionState::Active);
    assert_eq!(server.state(), SessionState::Active);
    (client, server)
}

fn expect_data(record: OpenedRecord, channel: DataChannel, plaintext: &[u8]) {
    match record {
        OpenedRecord::Data {
            channel: actual_channel,
            plaintext: actual_plaintext,
        } => {
            assert_eq!(actual_channel, channel);
            assert_eq!(actual_plaintext, plaintext);
        }
        _ => panic!("expected data record"),
    }
}

fn sequence(record: &[u8]) -> u64 {
    u64::from_be_bytes(record[4..12].try_into().unwrap())
}

fn channel_id(record: &[u8]) -> u16 {
    u16::from_be_bytes(record[2..4].try_into().unwrap())
}

#[test]
fn public_api_matches_the_whitepaper_record_vector() {
    let (mut client, mut server) = active_pair();
    let wire = client.seal_data(DataChannel::Menora, b"G301").unwrap();
    assert_eq!(
        hex::encode(&wire),
        "0100012d000000000000000000000004c130c2b21e8546f0c615ffecfe919005e67675c9"
    );
    expect_data(
        server.open_record(&wire).unwrap(),
        DataChannel::Menora,
        b"G301",
    );
}

#[test]
fn complete_bidirectional_session_uses_all_channels_and_guard_controls() {
    let (mut client, mut server) = active_pair();
    let channels = [
        DataChannel::Menora,
        DataChannel::Chanukkia,
        DataChannel::JomKippur,
        DataChannel::Tzafah,
    ];

    for (index, channel) in channels.into_iter().enumerate() {
        let client_plaintext = format!("client-{index}");
        let wire = client
            .seal_data(channel, client_plaintext.as_bytes())
            .unwrap();
        expect_data(
            server.open_record(&wire).unwrap(),
            channel,
            client_plaintext.as_bytes(),
        );

        let server_plaintext = format!("server-{index}");
        let wire = server
            .seal_data(channel, server_plaintext.as_bytes())
            .unwrap();
        expect_data(
            client.open_record(&wire).unwrap(),
            channel,
            server_plaintext.as_bytes(),
        );
    }

    let refresh = client.seal_refresh_required().unwrap();
    assert!(matches!(
        server.open_record(&refresh),
        Ok(OpenedRecord::RefreshRequired)
    ));
    assert_eq!(client.state(), SessionState::Active);
    assert_eq!(server.state(), SessionState::Active);

    let client_close = client.seal_close().unwrap();
    assert_eq!(client.state(), SessionState::Draining);
    assert!(matches!(
        server.open_record(&client_close),
        Ok(OpenedRecord::Close)
    ));
    assert_eq!(server.state(), SessionState::Draining);

    let server_close = server.seal_close().unwrap();
    assert_eq!(server.state(), SessionState::Closed);
    assert!(matches!(
        client.open_record(&server_close),
        Ok(OpenedRecord::Close)
    ));
    assert_eq!(client.state(), SessionState::Closed);
}

#[test]
fn commit_authentication_binds_exporter_and_application_context() {
    let mut client = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    let commit = client.seal_commit().unwrap();

    let mut different_exporter = [0_u8; 48];
    different_exporter[0] = 1;
    let mut server = construct(EndpointRole::Server, different_exporter, CONTEXT).unwrap();
    assert!(server.open_record(&commit).is_err());
    assert_eq!(server.state(), SessionState::Failed);

    let mut server = construct(
        EndpointRole::Server,
        exporter_bytes(),
        b"different-application",
    )
    .unwrap();
    assert!(server.open_record(&commit).is_err());
    assert_eq!(server.state(), SessionState::Failed);
}

#[test]
fn channel_and_direction_sequences_are_independent() {
    let (mut client, mut server) = active_pair();

    let client_menora_zero = client.seal_data(DataChannel::Menora, b"m0").unwrap();
    let client_tzafah_zero = client.seal_data(DataChannel::Tzafah, b"t0").unwrap();
    let client_menora_one = client.seal_data(DataChannel::Menora, b"m1").unwrap();
    let server_menora_zero = server.seal_data(DataChannel::Menora, b"s0").unwrap();

    assert_eq!(sequence(&client_menora_zero), 0);
    assert_eq!(sequence(&client_tzafah_zero), 0);
    assert_eq!(sequence(&client_menora_one), 1);
    assert_eq!(sequence(&server_menora_zero), 0);
    assert_eq!(channel_id(&client_menora_zero), 301);
    assert_eq!(channel_id(&client_tzafah_zero), 175);

    server.open_record(&client_menora_zero).unwrap();
    server.open_record(&client_tzafah_zero).unwrap();
    server.open_record(&client_menora_one).unwrap();
    client.open_record(&server_menora_zero).unwrap();
}

#[test]
fn payload_and_context_boundaries_roundtrip() {
    for context in [&[0_u8][..], &[0_u8; 255][..], &[0x00, 0xff][..]] {
        let session = construct(EndpointRole::Client, exporter_bytes(), context).unwrap();
        assert_eq!(session.state(), SessionState::Committing);
    }

    for payload in [&[][..], &[0x5a; 16_384][..]] {
        let (mut client, mut server) = active_pair();
        let wire = client.seal_data(DataChannel::JomKippur, payload).unwrap();
        assert_eq!(wire.len(), 32 + payload.len());
        expect_data(
            server.open_record(&wire).unwrap(),
            DataChannel::JomKippur,
            payload,
        );
    }
}

#[test]
fn equal_plaintext_is_separated_by_channel_and_direction() {
    let (mut client, mut server) = active_pair();
    let menora_c2s = client.seal_data(DataChannel::Menora, b"same").unwrap();
    let chanukkia_c2s = client.seal_data(DataChannel::Chanukkia, b"same").unwrap();
    let menora_s2c = server.seal_data(DataChannel::Menora, b"same").unwrap();

    assert_ne!(&menora_c2s[16..], &chanukkia_c2s[16..]);
    assert_ne!(&menora_c2s[16..], &menora_s2c[16..]);

    server.open_record(&menora_c2s).unwrap();
    server.open_record(&chanukkia_c2s).unwrap();
    client.open_record(&menora_s2c).unwrap();
}

#[test]
fn simultaneous_close_reaches_closed_on_both_sides() {
    let (mut client, mut server) = active_pair();
    let client_close = client.seal_close().unwrap();
    let server_close = server.seal_close().unwrap();
    assert_eq!(client.state(), SessionState::Draining);
    assert_eq!(server.state(), SessionState::Draining);

    client.open_record(&server_close).unwrap();
    server.open_record(&client_close).unwrap();
    assert_eq!(client.state(), SessionState::Closed);
    assert_eq!(server.state(), SessionState::Closed);
}
