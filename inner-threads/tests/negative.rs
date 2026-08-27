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
    let mut client = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    let mut server = construct(EndpointRole::Server, exporter_bytes(), CONTEXT).unwrap();
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
    (client, server)
}

fn valid_data() -> (Session, Session, Vec<u8>) {
    let (mut client, server) = pair();
    let record = client.seal_data(DataChannel::Menora, b"secret").unwrap();
    (client, server, record)
}

fn assert_terminal_rejection(mut server: Session, record: &[u8]) {
    assert!(server.open_record(record).is_err());
    assert_eq!(server.state(), SessionState::Failed);
    assert!(matches!(
        server.open_record(record),
        Err(Error::InvalidState)
    ));
}

fn assert_record_error(mut server: Session, record: &[u8], expected: Error) {
    assert!(matches!(server.open_record(record), Err(error) if error == expected));
    assert_eq!(server.state(), SessionState::Failed);
}

#[test]
fn parser_rejects_noncanonical_lengths_version_type_and_channel() {
    let (_, server, record) = valid_data();
    assert_terminal_rejection(server, &record[..record.len() - 1]);

    let (_, server, mut extended) = valid_data();
    extended.push(0);
    assert_terminal_rejection(server, &extended);

    for (offset, value) in [(0, 2), (1, 0x7f), (2, 0xff), (3, 0xff)] {
        let (_, server, mut malformed) = valid_data();
        malformed[offset] = value;
        assert_terminal_rejection(server, &malformed);
    }

    let (_, server, mut wrong_length) = valid_data();
    wrong_length[15] = wrong_length[15].wrapping_add(1);
    assert_terminal_rejection(server, &wrong_length);
}

#[test]
fn authentication_rejects_modified_header_ciphertext_and_tag_without_plaintext() {
    for offset in [3, 16, 37] {
        let (_, server, mut corrupted) = valid_data();
        corrupted[offset] ^= 1;
        assert_terminal_rejection(server, &corrupted);
    }
}

#[test]
fn replay_skipped_sequence_cross_channel_and_cross_direction_fail_closed() {
    let (mut client, mut server) = pair();
    let first = client.seal_data(DataChannel::Menora, b"first").unwrap();
    let second = client.seal_data(DataChannel::Menora, b"second").unwrap();
    assert!(matches!(
        server.open_record(&first),
        Ok(OpenedRecord::Data { .. })
    ));
    assert_record_error(server, &first, Error::InvalidRecord);

    let (_, server) = pair();
    assert_record_error(server, &second, Error::InvalidRecord);

    let (_, server, mut cross_channel) = valid_data();
    cross_channel[2..4].copy_from_slice(&99_u16.to_be_bytes());
    assert_terminal_rejection(server, &cross_channel);

    let (_, server, server_to_client) = {
        let (client, mut server) = pair();
        let record = server.seal_data(DataChannel::Menora, b"direction").unwrap();
        (client, server, record)
    };
    assert_terminal_rejection(server, &server_to_client);
}

#[test]
fn invalid_state_transitions_are_terminal() {
    let mut client = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    assert_eq!(
        client.seal_data(DataChannel::Menora, b"early"),
        Err(Error::InvalidState)
    );
    assert_eq!(client.state(), SessionState::Failed);

    let mut client = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    assert_eq!(client.seal_refresh_required(), Err(Error::InvalidState));
    assert_eq!(client.state(), SessionState::Failed);

    let mut client = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    assert_eq!(client.seal_close(), Err(Error::InvalidState));
    assert_eq!(client.state(), SessionState::Failed);

    let (mut active_client, _) = pair();
    let data = active_client
        .seal_data(DataChannel::Menora, b"valid-but-early")
        .unwrap();
    let server = construct(EndpointRole::Server, exporter_bytes(), CONTEXT).unwrap();
    assert_record_error(server, &data, Error::InvalidState);

    let (mut client, mut server) = pair();
    let pending_data = client.seal_data(DataChannel::Menora, b"pending").unwrap();
    let close = client.seal_close().unwrap();
    assert!(matches!(
        server.open_record(&close),
        Ok(OpenedRecord::Close)
    ));
    assert_terminal_rejection(server, &pending_data);
}

#[test]
fn invalid_record_type_channel_combinations_are_terminal() {
    let (_, server, mut data_on_guard) = valid_data();
    data_on_guard[2..4].copy_from_slice(&947_u16.to_be_bytes());
    assert_record_error(server, &data_on_guard, Error::InvalidRecord);

    let (_, server, mut commit_on_data) = valid_data();
    commit_on_data[1] = 0x80;
    assert_record_error(server, &commit_on_data, Error::InvalidRecord);

    let (_, server, mut close_with_payload) = valid_data();
    close_with_payload[1] = 0x82;
    close_with_payload[2..4].copy_from_slice(&947_u16.to_be_bytes());
    assert_record_error(server, &close_with_payload, Error::InvalidRecord);
}

#[test]
fn duplicate_commit_and_post_terminal_operations_are_rejected() {
    let mut client = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    let commit = client.seal_commit().unwrap();
    assert_eq!(client.seal_commit(), Err(Error::InvalidState));
    assert_eq!(client.state(), SessionState::Failed);

    let (_, mut server) = pair();
    assert!(server.open_record(&commit).is_err());
    assert_eq!(server.state(), SessionState::Failed);

    let (mut client, mut server) = pair();
    let close = client.seal_close().unwrap();
    server.open_record(&close).unwrap();
    let reply = server.seal_close().unwrap();
    client.open_record(&reply).unwrap();
    assert_eq!(client.state(), SessionState::Closed);
    assert!(matches!(
        client.open_record(&reply),
        Err(Error::InvalidState)
    ));
    assert_eq!(
        client.seal_data(DataChannel::Menora, b"late"),
        Err(Error::InvalidState)
    );
    assert_eq!(client.state(), SessionState::Closed);
}

#[test]
fn construction_and_plaintext_limits_are_strict() {
    assert!(matches!(
        construct(EndpointRole::Client, exporter_bytes(), b""),
        Err(Error::InvalidContext)
    ));
    assert!(matches!(
        construct(EndpointRole::Client, exporter_bytes(), &[0; 256]),
        Err(Error::InvalidContext)
    ));

    let (mut client, _) = pair();
    assert_eq!(
        client.seal_data(DataChannel::Menora, &[0; 16_385]),
        Err(Error::PlaintextTooLarge)
    );
    assert_eq!(client.state(), SessionState::Failed);
}

#[test]
fn abort_failed_and_closed_states_are_terminal() {
    let mut committing = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    committing.abort();
    assert_eq!(committing.state(), SessionState::Failed);
    assert_eq!(committing.seal_commit(), Err(Error::InvalidState));
    assert_eq!(committing.state(), SessionState::Failed);

    let (mut client, mut server) = pair();
    client.abort();
    assert_eq!(client.state(), SessionState::Failed);
    assert_eq!(
        client.seal_data(DataChannel::Menora, b"after abort"),
        Err(Error::InvalidState)
    );
    assert_eq!(client.state(), SessionState::Failed);

    let close = server.seal_close().unwrap();
    let (mut peer, _) = pair();
    peer.open_record(&close).unwrap();
    let reply = peer.seal_close().unwrap();
    server.open_record(&reply).unwrap();
    assert_eq!(server.state(), SessionState::Closed);

    server.abort();
    assert_eq!(server.state(), SessionState::Closed);
    assert_eq!(server.seal_commit(), Err(Error::InvalidState));
    assert_eq!(server.seal_refresh_required(), Err(Error::InvalidState));
    assert_eq!(server.seal_close(), Err(Error::InvalidState));
    assert_eq!(server.state(), SessionState::Closed);
}

#[test]
fn deterministic_test_feature_can_repeat_the_same_gcm_keystream() {
    let mut first = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    let mut second = construct(EndpointRole::Client, exporter_bytes(), CONTEXT).unwrap();
    let mut peer = construct(EndpointRole::Server, exporter_bytes(), CONTEXT).unwrap();

    first.seal_commit().unwrap();
    second.seal_commit().unwrap();
    let peer_commit = peer.seal_commit().unwrap();
    first.open_record(&peer_commit).unwrap();
    second.open_record(&peer_commit).unwrap();

    let first_wire = first.seal_data(DataChannel::Menora, b"AAAA").unwrap();
    let second_wire = second.seal_data(DataChannel::Menora, b"BBBB").unwrap();
    assert_eq!(&first_wire[..16], &second_wire[..16]);
    for offset in 0..4 {
        assert_eq!(
            first_wire[16 + offset] ^ second_wire[16 + offset],
            b'A' ^ b'B'
        );
    }
}
