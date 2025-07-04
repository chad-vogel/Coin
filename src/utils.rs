pub fn meets_difficulty(hash: &[u8], difficulty: u32) -> bool {
    for bit in 0..difficulty {
        let byte_idx = (bit / 8) as usize;
        let shift = 7 - (bit % 8);
        let byte = hash.get(byte_idx).copied().unwrap_or(0);
        if ((byte >> shift) & 1) != 0 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::meets_difficulty;

    #[test]
    fn difficulty_zero_always_true() {
        assert!(meets_difficulty(&[0xff], 0));
    }

    #[test]
    fn single_bit_difficulty() {
        assert!(meets_difficulty(&[0x7f], 1));
        assert!(!meets_difficulty(&[0x80], 1));
    }

    #[test]
    fn multi_byte_difficulty() {
        let hash = [0x00, 0x0f];
        assert!(meets_difficulty(&hash, 12));
        assert!(!meets_difficulty(&[0x00, 0x8f], 12));
    }
}
