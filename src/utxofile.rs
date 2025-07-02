use std::collections::HashMap;
use std::path::Path;

use bincode;
use rocksdb::{DB, Options};

const UTXO_KEY: &[u8] = b"utxos";

fn open_db(path: &Path) -> std::io::Result<DB> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    DB::open(&opts, path).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

fn serialize_error<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("serialize error: {e}"))
}

pub fn save_utxos<P: AsRef<Path>>(base: P, utxos: &HashMap<String, u64>) -> std::io::Result<()> {
    let db_path = base.as_ref().join("utxos");
    let db = open_db(&db_path)?;
    let data = bincode::serialize(utxos).map_err(serialize_error)?;
    db.put(UTXO_KEY, data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}

pub fn load_utxos<P: AsRef<Path>>(base: P) -> std::io::Result<HashMap<String, u64>> {
    let db_path = base.as_ref().join("utxos");
    let db = open_db(&db_path)?;
    match db.get(UTXO_KEY) {
        Ok(Some(val)) => bincode::deserialize(&val)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Ok(None) => Ok(HashMap::new()),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::IteratorMode;
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
        let db = open_db(&dir.path().join("utxos")).unwrap();
        assert_eq!(db.iterator(IteratorMode::Start).count(), 1);
    }

    #[test]
    fn invalid_data() {
        let dir = tempdir().unwrap();
        let db = open_db(&dir.path().join("utxos")).unwrap();
        db.put(UTXO_KEY, [0u8, 1u8]).unwrap();
        let res = load_utxos(dir.path());
        assert!(res.is_err());
    }
}
