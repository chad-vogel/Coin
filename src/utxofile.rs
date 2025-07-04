use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use bincode;

pub fn save_utxos<P: AsRef<Path>>(path: P, utxos: &HashMap<String, u64>) -> std::io::Result<()> {
    let data = bincode::serialize(utxos).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("serialize error: {e}"))
    })?;
    let mut f = File::create(path)?;
    f.write_all(&data)
}

pub fn load_utxos<P: AsRef<Path>>(path: P) -> std::io::Result<HashMap<String, u64>> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    bincode::deserialize(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), 1);
        map.insert("b".to_string(), 2);
        let dir = tempdir().unwrap();
        let path = dir.path().join("utxos.bin");
        save_utxos(&path, &map).unwrap();
        let loaded = load_utxos(&path).unwrap();
        assert_eq!(loaded, map);
    }

    #[test]
    fn invalid_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("utxos.bin");
        std::fs::write(&path, b"bad").unwrap();
        let res = load_utxos(&path);
        assert!(res.is_err());
    }
}
