use dep::protocol_types::{
    abis::function_selector::FunctionSelector, address::AztecAddress,
    constants::GENERATOR_INDEX__CONSTRUCTOR, hash::poseidon2_hash_with_separator, traits::ToField,
};

use crate::{
    context::{PrivateContext, PublicContext},
    oracle::get_contract_instance::{
        get_contract_instance, get_contract_instance_deployer_avm,
        get_contract_instance_initialization_hash_avm,
    },
};

pub fn mark_as_initialized_public(context: &mut PublicContext) {
    let init_nullifier =
        compute_unsiloed_contract_initialization_nullifier((*context).this_address());
    context.push_nullifier(init_nullifier);
}

pub fn mark_as_initialized_private(context: &mut PrivateContext) {
    let init_nullifier =
        compute_unsiloed_contract_initialization_nullifier((*context).this_address());
    context.push_nullifier(init_nullifier);
}

pub fn assert_is_initialized_public(context: &mut PublicContext) {
    let init_nullifier = compute_unsiloed_contract_initialization_nullifier(context.this_address());
    assert(context.nullifier_exists(init_nullifier, context.this_address()), "Not initialized");
}

pub fn assert_is_initialized_private(context: &mut PrivateContext) {
    let init_nullifier = compute_unsiloed_contract_initialization_nullifier(context.this_address());
    context.push_nullifier_read_request(init_nullifier);
}

fn compute_unsiloed_contract_initialization_nullifier(address: AztecAddress) -> Field {
    address.to_field()
}

pub fn assert_initialization_matches_address_preimage_public(context: PublicContext) {
    let address = context.this_address();
    let deployer = get_contract_instance_deployer_avm(address).unwrap();
    let initialization_hash = get_contract_instance_initialization_hash_avm(address).unwrap();
    let expected_init = compute_initialization_hash(context.selector(), context.get_args_hash());
    assert(initialization_hash == expected_init, "Initialization hash does not match");
    assert(
        (deployer.is_zero()) | (deployer == context.msg_sender()),
        "Initializer address is not the contract deployer",
    );
}

pub fn assert_initialization_matches_address_preimage_private(context: PrivateContext) {
    let address = context.this_address();
    let instance = get_contract_instance(address);
    let expected_init = compute_initialization_hash(context.selector(), context.get_args_hash());
    assert(instance.initialization_hash == expected_init, "Initialization hash does not match");
    assert(
        (instance.deployer.is_zero()) | (instance.deployer == context.msg_sender()),
        "Initializer address is not the contract deployer",
    );
}

/// This function is not only used in macros but it's also used by external people to check that an instance has been
/// initialized with the correct constructor arguments. Don't hide this unless you implement factory functionality.
pub fn compute_initialization_hash(
    init_selector: FunctionSelector,
    init_args_hash: Field,
) -> Field {
    poseidon2_hash_with_separator(
        [init_selector.to_field(), init_args_hash],
        GENERATOR_INDEX__CONSTRUCTOR,
    )
}
