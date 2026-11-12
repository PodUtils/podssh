//! Yggdrasil's transform of a key, which Ironwood's bloom filters carry in
//! the key's place: the key of the /64 subnet that the key's address heads,
//! so that a lookup by an address's prefix finds the key. The address takes
//! the key's leading zero bits as a count, skips the first one, and keeps
//! the next bits; the subnet keeps 48 of them. Read back as a key, each bit
//! past those reads as one.

/// The bits after the leading zeros and their end that a subnet keeps.
const SUBNET_BITS: usize = 48;

/// The key of `key`'s subnet, as Yggdrasil's own nodes transform it.
pub fn subnet_key(key: &[u8; 32]) -> [u8; 32] {
    let zeros = key.iter().position(|b| *b != 0).map_or(256, |i| i * 8 + key[i].leading_zeros() as usize);
    // The address counts the leading zeros in one byte.
    let kept = (zeros.min(255) + 1 + SUBNET_BITS).min(256);
    let mut out = *key;
    for bit in kept..256 {
        out[bit / 8] |= 0x80 >> (bit % 8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(text: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap()).collect();
        bytes.try_into().unwrap()
    }

    /// Keys and their subnets' keys from yggdrasil-go v0.5.15's own
    /// `address.SubnetForKey(key).GetKey()`.
    #[test]
    fn a_key_s_transform_is_yggdrasil_go_s() {
        let vectors = [
            (
                "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
                "3b6a27bcceb6bfffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            (
                "b7ecd7d860c957c331a2dc52940ccd41e9b1041e00cc5c43a738ae5157cf317e",
                "b7ecd7d860c97fffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            (
                "bb9f546fdb89c003b97cb242ccac2c49243966ee8cad0f2ab200560fc43a3e30",
                "bb9f546fdb89ffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            (
                "1ff449454787a63192c08dbbf6a97edb615aba0bb1618a3ee9b9a55d4631a05d",
                "1ff449454787afffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            (
                "214db55b6e0103d738c903553203f36cc4531ea9e174d9455ff5a8e5a613e717",
                "214db55b6e011fffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            (
                "fb5cc038e8808a7c94a71f8318161dd62ec0e34bb346b0e03b678d3120f88b3f",
                "fb5cc038e880ffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        ];
        for (key, subnet) in vectors {
            assert_eq!(subnet_key(&hex32(key)), hex32(subnet), "{key}");
        }
        assert_eq!(subnet_key(&[0; 32]), [0; 32], "no bit past the count");
    }
}
