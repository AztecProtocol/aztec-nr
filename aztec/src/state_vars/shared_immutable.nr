use crate::{
    context::{PrivateContext, PublicContext, UnconstrainedContext}, oracle::storage::storage_read,
    state_vars::storage::Storage
};
use dep::protocol_types::{constants::INITIALIZATION_SLOT_SEPARATOR, traits::{Deserialize, Serialize}};

// Just like PublicImmutable but with the ability to read from private functions.
struct SharedImmutable<T, Context>{
    context: Context,
    storage_slot: Field,
}

impl<T, Context> Storage<T> for SharedImmutable<T, Context> {}

impl<T, Context> SharedImmutable<T, Context> {
    pub fn new(
        // Note: Passing the contexts to new(...) just to have an interface compatible with a Map.
        context: Context,
        storage_slot: Field
    ) -> Self {
        assert(storage_slot != 0, "Storage slot 0 not allowed. Storage slots must start from 1.");
        Self { context, storage_slot }
    }
}

impl<T> SharedImmutable<T, &mut PublicContext> {
    // Intended to be only called once. 
    pub fn initialize<T_SERIALIZED_LEN>(self, value: T) where T: Serialize<T_SERIALIZED_LEN> {
        // We check that the struct is not yet initialized by checking if the initialization slot is 0
        let initialization_slot = INITIALIZATION_SLOT_SEPARATOR + self.storage_slot;
        let init_field: Field = self.context.storage_read(initialization_slot);
        assert(init_field == 0, "SharedImmutable already initialized");

        // We populate the initialization slot with a non-zero value to indicate that the struct is initialized
        self.context.storage_write(initialization_slot, 0xdead);
        self.context.storage_write(self.storage_slot, value);
    }

    pub fn read_public<T_SERIALIZED_LEN>(self) -> T where T: Deserialize<T_SERIALIZED_LEN> {
        self.context.storage_read(self.storage_slot)
    }
}

impl<T> SharedImmutable<T, UnconstrainedContext> {
    unconstrained pub fn read_public<T_SERIALIZED_LEN>(self) -> T where T: Deserialize<T_SERIALIZED_LEN> {
        self.context.storage_read(self.storage_slot)
    }
}

impl<T> SharedImmutable<T, &mut PrivateContext> {
    pub fn read_private<T_SERIALIZED_LEN>(self) -> T  where T: Deserialize<T_SERIALIZED_LEN> {
        let header = self.context.get_header();
        let mut fields = [0; T_SERIALIZED_LEN];

        for i in 0..fields.len() {
            fields[i] =
                header.public_storage_historical_read(
                    self.storage_slot + i as Field,
                    (*self.context).this_address()
                );
        }
        T::deserialize(fields)
    }
}
