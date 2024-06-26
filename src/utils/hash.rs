use md5::{Digest, Md5};

pub fn calculate_md5_hash(data: String) -> String {
    // Create a new MD5 hasher instance
    let mut hasher = Md5::new();

    // Update the hasher with the data
    hasher.update(data.as_bytes());

    // Compute the hash
    let result = hasher.finalize();

    // Convert the hash to a byte array
    let hash_bytes = result.as_slice();

    // Convert the byte array to a hexadecimal string representation
    let hash_str = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    hash_str.to_uppercase()
}
