#![no_std]

#[repr(C)]
pub struct Uint256 {
    pub hi: u128,
    pub lo: u128,
}

impl Uint256 {
    pub const fn zero() -> Self {
        Self { hi: 0, lo: 0 }
    }

    pub fn add_one(&mut self) {
        if self.lo == u128::MAX {
            self.lo = 0;
            self.hi = self.hi.saturating_add(1);
        } else {
            self.lo += 1;
        }
    }

    pub fn sub_one(&mut self) {
        if self.lo == 0 {
            self.lo = u128::MAX;
            if self.hi > 0 {
                self.hi -= 1;
            }
        } else {
            self.lo -= 1;
        }
    }
}

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn get(key: i32) -> i64;
    fn set(key: i32, value: i64);
    fn get_u128(base: i32) -> (i64, i64);
    fn set_u128(base: i32, lo: i64, hi: i64);
    fn get_u256(base: i32) -> (i64, i64, i64, i64);
    fn set_u256(base: i32, a: i64, b: i64, c: i64, d: i64);
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
mod host_funcs {
    #[cfg(test)]
    use once_cell::sync::Lazy;
    #[cfg(test)]
    use std::collections::HashMap;
    #[cfg(test)]
    use std::sync::Mutex;

    #[cfg(test)]
    static STORE: Lazy<Mutex<HashMap<i32, i64>>> = Lazy::new(|| Mutex::new(HashMap::new()));

    #[allow(unused_variables)]
    pub unsafe fn get(key: i32) -> i64 {
        #[cfg(test)]
        {
            let store = STORE.lock().unwrap();
            *store.get(&key).unwrap_or(&0)
        }
        #[cfg(not(test))]
        {
            0
        }
    }

    #[allow(unused_variables)]
    pub unsafe fn set(key: i32, value: i64) {
        #[cfg(test)]
        {
            let mut store = STORE.lock().unwrap();
            store.insert(key, value);
        }
    }

    #[allow(unused_variables)]
    pub unsafe fn get_u128(base: i32) -> (i64, i64) {
        #[cfg(test)]
        {
            let store = STORE.lock().unwrap();
            (
                *store.get(&base).unwrap_or(&0),
                *store.get(&(base + 1)).unwrap_or(&0),
            )
        }
        #[cfg(not(test))]
        {
            (0, 0)
        }
    }

    #[allow(unused_variables)]
    pub unsafe fn set_u128(base: i32, lo: i64, hi: i64) {
        #[cfg(test)]
        {
            let mut store = STORE.lock().unwrap();
            store.insert(base, lo);
            store.insert(base + 1, hi);
        }
    }

    #[allow(unused_variables)]
    pub unsafe fn get_u256(base: i32) -> (i64, i64, i64, i64) {
        #[cfg(test)]
        {
            let store = STORE.lock().unwrap();
            (
                *store.get(&base).unwrap_or(&0),
                *store.get(&(base + 1)).unwrap_or(&0),
                *store.get(&(base + 2)).unwrap_or(&0),
                *store.get(&(base + 3)).unwrap_or(&0),
            )
        }
        #[cfg(not(test))]
        {
            (0, 0, 0, 0)
        }
    }

    #[allow(unused_variables)]
    pub unsafe fn set_u256(base: i32, a: i64, b: i64, c: i64, d: i64) {
        #[cfg(test)]
        {
            let mut store = STORE.lock().unwrap();
            store.insert(base, a);
            store.insert(base + 1, b);
            store.insert(base + 2, c);
            store.insert(base + 3, d);
        }
    }
}

pub unsafe fn read_i64(key: i32) -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        get(key)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        host_funcs::get(key)
    }
}

pub unsafe fn write_i64(key: i32, val: i64) {
    #[cfg(target_arch = "wasm32")]
    {
        set(key, val);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        host_funcs::set(key, val);
    }
}

pub unsafe fn read_u128(base: i32) -> u128 {
    let (lo, hi) = {
        #[cfg(target_arch = "wasm32")]
        {
            get_u128(base)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            host_funcs::get_u128(base)
        }
    };
    ((hi as u64 as u128) << 64) | (lo as u64 as u128)
}

pub unsafe fn write_u128(base: i32, val: u128) {
    let lo = (val & ((1u128 << 64) - 1)) as u64;
    let hi = (val >> 64) as u64;
    #[cfg(target_arch = "wasm32")]
    {
        set_u128(base, lo as i64, hi as i64);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        host_funcs::set_u128(base, lo as i64, hi as i64);
    }
}

pub unsafe fn read_u256(base: i32) -> Uint256 {
    let (a, b, c, d) = {
        #[cfg(target_arch = "wasm32")]
        {
            get_u256(base)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            host_funcs::get_u256(base)
        }
    };
    let lo = ((b as u64 as u128) << 64) | (a as u64 as u128);
    let hi = ((d as u64 as u128) << 64) | (c as u64 as u128);
    Uint256 { hi, lo }
}

pub unsafe fn write_u256(base: i32, val: &Uint256) {
    let a = (val.lo & ((1u128 << 64) - 1)) as u64;
    let b = (val.lo >> 64) as u64;
    let c = (val.hi & ((1u128 << 64) - 1)) as u64;
    let d = (val.hi >> 64) as u64;
    #[cfg(target_arch = "wasm32")]
    {
        set_u256(base, a as i64, b as i64, c as i64, d as i64);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        host_funcs::set_u256(base, a as i64, b as i64, c as i64, d as i64);
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u256_add_sub() {
        let mut v = Uint256::zero();
        v.add_one();
        assert_eq!(v.lo, 1);
        v.lo = u128::MAX - 1;
        v.add_one();
        v.add_one();
        assert_eq!(v.lo, 0);
        assert_eq!(v.hi, 1);
        v.sub_one();
        assert_eq!(v.hi, 0);
        assert_eq!(v.lo, u128::MAX);
    }

    #[test]
    fn read_write_roundtrip() {
        unsafe {
            write_i64(1, 42);
            assert_eq!(read_i64(1), 42);
            let val128 = 12345678901234567890u128;
            write_u128(2, val128);
            assert_eq!(read_u128(2), val128);
            let val256 = Uint256 { hi: 5, lo: 6 };
            write_u256(10, &val256);
            let got = read_u256(10);
            assert_eq!(got.hi, 5);
            assert_eq!(got.lo, 6);
        }
    }
}
