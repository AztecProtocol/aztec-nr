use dep::protocol_types::traits::Empty;

// These inputs will likely go away once the AVM processes 1 public kernel per enqueued call.
struct PublicContextInputs {
    args_hash: Field,
    is_static_call: bool
}

impl Empty for PublicContextInputs {
    fn empty() -> Self {
        PublicContextInputs {
            args_hash: 0,
            is_static_call: false
        }
    }
}
