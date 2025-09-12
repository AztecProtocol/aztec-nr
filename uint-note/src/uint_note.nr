use dep::aztec::{
    context::{PrivateContext, PublicContext},
    history::nullifier_inclusion::ProveNullifierInclusion,
    keys::getters::{get_nsk_app, get_public_keys},
    macros::notes::custom_note,
    messages::logs::note,
    note::note_interface::{NoteHash, NoteType},
    oracle::random::random,
    protocol_types::{
        address::AztecAddress,
        constants::{
            GENERATOR_INDEX__NOTE_HASH, GENERATOR_INDEX__NOTE_NULLIFIER,
            GENERATOR_INDEX__PARTIAL_NOTE_VALIDITY_COMMITMENT, PRIVATE_LOG_SIZE_IN_FIELDS,
        },
        hash::{compute_siloed_nullifier, poseidon2_hash_with_separator},
        traits::{Deserialize, FromField, Hash, Packable, Serialize, ToField},
    },
};

/// A private note representing a numeric value associated to an account (e.g. a token balance).
#[derive(Eq, Serialize, Packable)]
#[custom_note]
pub struct UintNote {
    owner: AztecAddress,
    randomness: Field,
    value: u128,
}

impl NoteHash for UintNote {
    fn compute_note_hash(self, storage_slot: Field) -> Field {
        let private_content = UintPartialNotePrivateContent { owner: self.owner, randomness: self.randomness };
        let partial_note = PartialUintNote {
            commitment: private_content.compute_partial_commitment(storage_slot),
        };
        partial_note.compute_complete_note_hash(self.value)
    }

    fn compute_nullifier(
        self,
        context: &mut PrivateContext,
        note_hash_for_nullify: Field,
    ) -> Field {
        let owner_npk_m = get_public_keys(self.owner).npk_m;
        let owner_npk_m_hash = owner_npk_m.hash();
        let secret = context.request_nsk_app(owner_npk_m_hash);
        poseidon2_hash_with_separator(
            [note_hash_for_nullify, secret],
            GENERATOR_INDEX__NOTE_NULLIFIER,
        )
    }

    unconstrained fn compute_nullifier_unconstrained(self, note_hash_for_nullify: Field) -> Field {
        let owner_npk_m = get_public_keys(self.owner).npk_m;
        let owner_npk_m_hash = owner_npk_m.hash();
        let secret = get_nsk_app(owner_npk_m_hash);
        poseidon2_hash_with_separator(
            [note_hash_for_nullify, secret],
            GENERATOR_INDEX__NOTE_NULLIFIER,
        )
    }
}

impl UintNote {
    pub fn new(value: u128, owner: AztecAddress) -> Self {
        let randomness = random();
        Self { value, owner, randomness }
    }

    pub fn get_value(self) -> u128 {
        self.value
    }

    pub fn get_owner(self) -> AztecAddress {
        self.owner
    }

    pub fn partial(
        owner: AztecAddress,
        storage_slot: Field,
        context: &mut PrivateContext,
        recipient: AztecAddress,
        completer: AztecAddress,
    ) -> PartialUintNote {
        let randomness = random();
        let commitment = UintPartialNotePrivateContent { owner, randomness }
            .compute_partial_commitment(storage_slot);

        let private_log_content = PrivateUintPartialNotePrivateLogContent {
            owner,
            randomness,
            public_log_tag: commitment,
        };

        let encrypted_log =
            note::compute_partial_note_log(private_log_content, storage_slot, recipient);
        let length = encrypted_log.len();
        context.emit_private_log(encrypted_log, length);

        let partial_note = PartialUintNote { commitment };

        let validity_commitment = partial_note.compute_validity_commitment(completer);
        context.push_nullifier(validity_commitment);

        partial_note
    }
}

#[derive(Packable)]
struct UintPartialNotePrivateContent {
    owner: AztecAddress,
    randomness: Field,
}

impl UintPartialNotePrivateContent {
    fn compute_partial_commitment(self, storage_slot: Field) -> Field {
        let packed = self.pack();
        let mut concat = packed;
        concat.push(storage_slot);
        poseidon2_hash_with_separator(
            concat,
            GENERATOR_INDEX__NOTE_HASH,
        )
    }
}

#[derive(Packable)]
struct PrivateUintPartialNotePrivateLogContent {
    public_log_tag: Field,
    owner: AztecAddress,
    randomness: Field,
}

impl NoteType for PrivateUintPartialNotePrivateLogContent {
    fn get_id() -> Field {
        UintNote::get_id()
    }
}

#[derive(Packable, Serialize, Deserialize, Eq)]
pub struct PartialUintNote {
    commitment: Field,
}

// Use const instead of global for constants
const NOTE_COMPLETION_LOG_LENGTH: u32 = 2;

impl PartialUintNote {
    pub fn complete(self, context: &mut PublicContext, completer: AztecAddress, value: u128) {
        assert(value != 0);
        let validity_commitment = self.compute_validity_commitment(completer);
        assert(
            context.nullifier_exists(validity_commitment, context.this_address()),
        );
        context.emit_public_log(self.compute_note_completion_log(value));
        context.push_note_hash(self.compute_complete_note_hash(value));
    }

    pub fn complete_from_private(
        self,
        context: &mut PrivateContext,
        completer: AztecAddress,
        value: u128,
    ) {
        let validity_commitment = self.compute_validity_commitment(completer);
        let siloed_validity_commitment =
            compute_siloed_nullifier(context.this_address(), validity_commitment);
        context.get_block_header().prove_nullifier_inclusion(siloed_validity_commitment);

        context.emit_private_log(
            self.compute_note_completion_log_padded_for_private_log(value),
            NOTE_COMPLETION_LOG_LENGTH,
        );
        context.push_note_hash(self.compute_complete_note_hash(value));
    }

    pub fn compute_validity_commitment(self, completer: AztecAddress) -> Field {
        poseidon2_hash_with_separator(
            [self.commitment, completer.to_field()],
            GENERATOR_INDEX__PARTIAL_NOTE_VALIDITY_COMMITMENT,
        )
    }

    fn compute_note_completion_log(self, value: u128) -> [Field; NOTE_COMPLETION_LOG_LENGTH] {
        [self.commitment, value.to_field()]
    }

    fn compute_note_completion_log_padded_for_private_log(
        self,
        value: u128,
    ) -> [Field; PRIVATE_LOG_SIZE_IN_FIELDS] {
        let note_completion_log = self.compute_note_completion_log(value);
        let mut padded_log = note_completion_log;
        for i in NOTE_COMPLETION_LOG_LENGTH..PRIVATE_LOG_SIZE_IN_FIELDS {
            padded_log[i] = 0;
        }
        padded_log
    }

    fn compute_complete_note_hash(self, value: u128) -> Field {
        poseidon2_hash_with_separator(
            [self.commitment, value.to_field()],
            GENERATOR_INDEX__NOTE_HASH,
        )
    }
}

impl ToField for PartialUintNote {
    fn to_field(self) -> Field {
        self.commitment
    }
}

impl FromField for PartialUintNote {
    fn from_field(field: Field) -> Self {
        Self { commitment: field }
    }
}

mod test {
    use super::{
        PartialUintNote, PrivateUintPartialNotePrivateLogContent, UintNote,
        UintPartialNotePrivateContent,
    };
    use dep::aztec::{
        note::note_interface::NoteHash,
        protocol_types::{address::AztecAddress, traits::{Deserialize, FromField, Packable}},
        utils::array::subarray,
    };

    const value: u128 = 17;
    const randomness: Field = 42;
    const owner: AztecAddress = AztecAddress::from_field(50);
    const storage_slot: Field = 13;

    #[test]
    fn note_hash_matches_completed_partial_note_hash() {
        let note = UintNote { value, randomness, owner };
        let note_hash = note.compute_note_hash(storage_slot);

        let partial_note_private_content = UintPartialNotePrivateContent { owner, randomness };

        let partial_note = PartialUintNote {
            commitment: partial_note_private_content.compute_partial_commitment(storage_slot),
        };
        let completed_partial_note_hash = partial_note.compute_complete_note_hash(value);

        assert_eq(note_hash, completed_partial_note_hash);
    }

    #[test]
    fn unpack_from_partial_note_encoding() {
        let note = UintNote { value, randomness, owner };

        let partial_note_private_content = UintPartialNotePrivateContent { owner, randomness };
        let commitment = partial_note_private_content.compute_partial_commitment(storage_slot);

        let private_log_content = PrivateUintPartialNotePrivateLogContent {
            owner,
            randomness,
            public_log_tag: commitment,
        };
        let partial_note = PartialUintNote::deserialize([commitment]);

        assert_eq(
            private_log_content.pack()[0],
            partial_note.compute_note_completion_log(value)[0],
        );

        let private_log_without_public_tag: [_; 2] = subarray(private_log_content.pack(), 1);
        let public_log_without_tag: [_; 1] =
            subarray(partial_note.compute_note_completion_log(value), 1);

        assert_eq(private_log_without_public_tag.concat(public_log_without_tag), note.pack());
    }
}