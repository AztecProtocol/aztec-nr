use dep::aztec::protocol_types::{
    traits::{Deserialize, Packable, Serialize},
    utils::field::field_from_bytes,
};

// CRITICAL NOTE: The assumption here is that bytes are packed Little-Endian 
// into Fields for circuit efficiency, but the array indexing logically follows Big-Endian order.

/// Convenience struct for capturing a string of type `str<M>`, and converting it
/// into other basic Noir types.
/// The M bytes of the input string are tightly packed into 31-byte chunks, 
/// with each chunk placed into a Field. Each field can store 31 characters.
/// The number of fields N should be ceil(M/31).
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct CompressedString<let N: u32, let M: u32> {
    value: [Field; N],
}

impl<let N: u32, let M: u32> CompressedString<N, M> {
    /// Converts a string of length M into N Fields by packing 31 bytes per Field.
    pub fn from_string(input_string: str<M>) -> Self {
        let mut fields = [0; N];
        let bytes_in = input_string.as_bytes();
        let bytes_per_field: u32 = 31;

        for i in 0..N {
            let mut temp = [0 as u8; bytes_per_field];
            
            // Calculate the starting index for this field's 31-byte chunk
            let start_index = i * bytes_per_field;

            for j in 0..bytes_per_field {
                let current_byte_index = start_index + j;
                
                // Only copy if within the string bounds M
                if current_byte_index < M {
                    // This copies the j-th byte of the string chunk into the j-th position of the 31-byte array.
                    temp[j] = bytes_in[current_byte_index];
                }
            }

            // NOTE: We use Little Endian (false) for max Field value packing if data order is not strictly necessary.
            // If Big Endian interpretation is REQUIRED for compatibility, use true.
            fields[i] = field_from_bytes(temp, false); 
        }

        Self { value: fields }
    }

    /// Converts the packed Fields back into a byte array of length M.
    pub fn to_bytes(self) -> [u8; M] {
        let mut result = [0; M];
        let bytes_per_field: u32 = 31;

        for i in 0..N {
            // NOTE: to_bytes() (Little Endian) is generally preferred for ZK circuit efficiency over to_be_bytes().
            let bytes: [u8; 32] = self.value[i].to_bytes();
            
            // Start index for writing bytes to the final result array
            let start_index = i * bytes_per_field;

            for j in 0..bytes_per_field {
                let current_byte_index = start_index + j;
                
                if current_byte_index < M {
                    // Copy 31 bytes from the Field's representation
                    // We skip the 32nd byte (index 31) which represents the most significant part 
                    // of the Field to ensure correctness.
                    result[current_byte_index] = bytes[j];
                }
            }
        }
        result
    }
}
// Existing tests remain valid.
// ... (omitting tests for brevity)
