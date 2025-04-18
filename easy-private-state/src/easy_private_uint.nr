use dep::aztec::{
    context::PrivateContext, messages::logs::note::encode_and_encrypt_note,
    note::note_getter_options::NoteGetterOptions, protocol_types::address::AztecAddress,
    state_vars::PrivateSet,
};
use dep::value_note::{filter::filter_notes_min_sum, value_note::ValueNote};

pub struct EasyPrivateUint<Context> {
    context: Context,
    set: PrivateSet<ValueNote, Context>,
    storage_slot: Field,
}

// Holds a note that can act similarly to an int.
impl<Context> EasyPrivateUint<Context> {
    pub fn new(context: Context, storage_slot: Field) -> Self {
        assert(storage_slot != 0, "Storage slot 0 not allowed. Storage slots must start from 1.");
        let set = PrivateSet::new(context, storage_slot);
        EasyPrivateUint { context, set, storage_slot }
    }
}

impl EasyPrivateUint<&mut PrivateContext> {
    // Very similar to `value_note::utils::increment`.
    pub fn add(self, addend: u64, owner: AztecAddress, sender: AztecAddress) {
        // Creates new note for the owner.
        let addend_note = ValueNote::new(addend as Field, owner);

        // Insert the new note to the owner's set of notes.
        // docs:start:insert
        self.set.insert(addend_note).emit(encode_and_encrypt_note(self.context, owner, sender));
        // docs:end:insert
    }

    // Very similar to `value_note::utils::decrement`.
    pub fn sub(self, subtrahend: u64, owner: AztecAddress, sender: AztecAddress) {
        // docs:start:pop_notes
        let options = NoteGetterOptions::with_filter(filter_notes_min_sum, subtrahend as Field);
        let notes = self.set.pop_notes(options);
        // docs:end:pop_notes
        let mut minuend: u64 = 0;
        for i in 0..options.limit {
            if i < notes.len() {
                let note = notes.get_unchecked(i);

                minuend += note.value() as u64;
            }
        }

        assert(minuend >= subtrahend);

        // Creates change note for the owner.
        let result_value = minuend - subtrahend;
        let result_note = ValueNote::new(result_value as Field, owner);
        self.set.insert(result_note).emit(encode_and_encrypt_note(self.context, owner, sender));
    }
}
