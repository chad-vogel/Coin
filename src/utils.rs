pub fn meets_difficulty(hash: &[u8], difficulty: u32) -> bool {
    for i in 0..difficulty {
        if hash.get(i as usize).copied().unwrap_or(0) != 0 {
            return false;
        }
    }
    true
}
