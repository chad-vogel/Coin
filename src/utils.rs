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
