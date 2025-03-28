use crate::{
    discovery::{
        ComputeNoteHashAndNullifier,
        MAX_LOG_CONTENT_LEN,
        nonce_discovery::{attempt_note_nonce_discovery, DiscoveredNoteInfo},
    },
    oracle,
    utils::array,
};
use protocol_types::{
    address::AztecAddress, constants::MAX_NOTE_HASHES_PER_TX, debug_log::debug_log_format,
};

/// The number of fields in a private note log content that are not the note's packed representation.
global PRIVATE_NOTE_LOG_CONTENT_NON_NOTE_FIELDS_LEN: u32 = 1;

/// The maximum length of the packed representation of a note's contents. This is limited by private log size,
/// encryption overhead and extra fields in the log (e.g. log type id, storage slot, etc.).
pub global MAX_NOTE_PACKED_LEN: u32 =
    MAX_LOG_CONTENT_LEN - PRIVATE_NOTE_LOG_CONTENT_NON_NOTE_FIELDS_LEN;

pub unconstrained fn process_private_note_log<Env>(
    contract_address: AztecAddress,
    tx_hash: Field,
    unique_note_hashes_in_tx: BoundedVec<Field, MAX_NOTE_HASHES_PER_TX>,
    first_nullifier_in_tx: Field,
    recipient: AztecAddress,
    compute_note_hash_and_nullifier: ComputeNoteHashAndNullifier<Env>,
    log_metadata: u64,
    log_content: BoundedVec<Field, MAX_LOG_CONTENT_LEN>,
) {
    let (note_type_id, storage_slot, packed_note) =
        decode_private_note_log(log_metadata, log_content);

    attempt_note_discovery(
        contract_address,
        tx_hash,
        unique_note_hashes_in_tx,
        first_nullifier_in_tx,
        recipient,
        compute_note_hash_and_nullifier,
        storage_slot,
        note_type_id,
        packed_note,
    );
}

/// Attempts discovery of a note given information about its contents and the transaction in which it is
/// suspected the note was created.
pub unconstrained fn attempt_note_discovery<Env>(
    contract_address: AztecAddress,
    tx_hash: Field,
    unique_note_hashes_in_tx: BoundedVec<Field, MAX_NOTE_HASHES_PER_TX>,
    first_nullifier_in_tx: Field,
    recipient: AztecAddress,
    compute_note_hash_and_nullifier: ComputeNoteHashAndNullifier<Env>,
    storage_slot: Field,
    note_type_id: Field,
    packed_note: BoundedVec<Field, MAX_NOTE_PACKED_LEN>,
) {
    let discovered_notes = attempt_note_nonce_discovery(
        unique_note_hashes_in_tx,
        first_nullifier_in_tx,
        compute_note_hash_and_nullifier,
        contract_address,
        storage_slot,
        note_type_id,
        packed_note,
    );

    debug_log_format(
        "Discovered {0} notes from a private log",
        [discovered_notes.len() as Field],
    );

    array::for_each_in_bounded_vec(
        discovered_notes,
        |discovered_note: DiscoveredNoteInfo, _| {
            // TODO:(#10728): handle notes that fail delivery. This could be due to e.g. a temporary node connectivity
            // issue, and we should perhaps not have marked the tag index as taken.
            assert(
                oracle::message_discovery::deliver_note(
                    contract_address,
                    storage_slot,
                    discovered_note.nonce,
                    packed_note,
                    discovered_note.note_hash,
                    discovered_note.inner_nullifier,
                    tx_hash,
                    recipient,
                ),
                "Failed to deliver note",
            );
        },
    );
}

fn decode_private_note_log(
    log_metadata: u64,
    log_content: BoundedVec<Field, MAX_LOG_CONTENT_LEN>,
) -> (Field, Field, BoundedVec<Field, MAX_NOTE_PACKED_LEN>) {
    let note_type_id = log_metadata as Field; // TODO: make note type id not be a full field

    assert(
        log_content.len() > PRIVATE_NOTE_LOG_CONTENT_NON_NOTE_FIELDS_LEN,
        f"Invalid private note log: all private note logs must have at least {PRIVATE_NOTE_LOG_CONTENT_NON_NOTE_FIELDS_LEN} fields",
    );

    // If PRIVATE_NOTE_LOG_CONTENT_NON_NOTE_FIELDS_LEN is changed, causing the assertion below to fail, then the destructuring of
    // the private note log encoding below must be updated as well.
    std::static_assert(
        PRIVATE_NOTE_LOG_CONTENT_NON_NOTE_FIELDS_LEN == 1,
        "unexpected value for PRIVATE_NOTE_LOG_CONTENT_NON_NOTE_FIELDS_LEN",
    );

    // We currently have a single field that is not the note's packed representation, which is the storage slot.
    let storage_slot = log_content.get(0);
    let packed_note = array::subbvec(log_content, PRIVATE_NOTE_LOG_CONTENT_NON_NOTE_FIELDS_LEN);

    (note_type_id, storage_slot, packed_note)
}
