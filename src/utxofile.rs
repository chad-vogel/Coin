use std::collections::HashMap;
use std::path::Path;

use rocksdb::{DB, Options};

use bincode;

fn open_db(path: &Path, create: bool) -> std::io::Result<DB> {
    let mut opts = Options::default();
    opts.create_if_missing(create);
    DB::open(&opts, path).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

pub fn save_utxos<P: AsRef<Path>>(path: P, utxos: &HashMap<String, u64>) -> std::io::Result<()> {
    let db = open_db(path.as_ref(), true)?;
    let data = bincode::serialize(utxos).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("serialize error: {e}"))
    })?;
    db.put(b"utxos", data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

pub fn load_utxos<P: AsRef<Path>>(path: P) -> std::io::Result<HashMap<String, u64>> {
    let db = open_db(path.as_ref(), false)?;
    let data = db
        .get(b"utxos")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "utxos"))?;
    bincode::deserialize(&data).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
        save_utxos(dir.path(), &map).unwrap();
        let loaded = load_utxos(dir.path()).unwrap();
        assert_eq!(loaded, map);
    }

    #[test]
    fn invalid_data() {
        let dir = tempdir().unwrap();
        let db = open_db(dir.path(), true).unwrap();
        db.put(b"utxos", b"bad").unwrap();
        let res = load_utxos(dir.path());
        assert!(res.is_err());
    }
}
