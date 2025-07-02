extern "C" {
    fn get(key: i32) -> i64;
    fn set(key: i32, value: i64);
}

const TOTAL_SUPPLY_BASE: i32 = 0;
const ALICE_BASE: i32 = 4;
const BOB_BASE: i32 = 8;

#[derive(Copy, Clone)]
struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    const fn zero() -> Self {
        U256 { hi: 0, lo: 0 }
    }

    fn is_zero(&self) -> bool {
        self.hi == 0 && self.lo == 0
    }

    fn add_one(&mut self) {
        if self.lo == u128::MAX {
            self.lo = 0;
            self.hi += 1;
        } else {
            self.lo += 1;
        }
    }

    fn sub_one(&mut self) {
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

unsafe fn read_u128(base: i32) -> u128 {
    let low = u64::from_le_bytes(get(base).to_le_bytes());
    let high = u64::from_le_bytes(get(base + 1).to_le_bytes());
    ((high as u128) << 64) | (low as u128)
}

unsafe fn write_u128(base: i32, val: u128) {
    let low = (val & ((1u128 << 64) - 1)) as u64;
    let high = (val >> 64) as u64;
    set(base, i64::from_le_bytes(low.to_le_bytes()));
    set(base + 1, i64::from_le_bytes(high.to_le_bytes()));
}

unsafe fn read_u256(base: i32) -> U256 {
    U256 {
        lo: read_u128(base),
        hi: read_u128(base + 2),
    }
}

unsafe fn write_u256(base: i32, val: U256) {
    write_u128(base, val.lo);
    write_u128(base + 2, val.hi);
}

#[no_mangle]
pub extern "C" fn main() -> i64 {
    unsafe {
        let mut total = read_u256(TOTAL_SUPPLY_BASE);
        if total.is_zero() {
            let initial = U256 {
                hi: 0,
                lo: 100_000_000_000_000_000_000_000_000u128,
            };
            write_u256(ALICE_BASE, initial);
            write_u256(TOTAL_SUPPLY_BASE, initial);
            return 0;
        }

        let mut alice = read_u256(ALICE_BASE);
        if !alice.is_zero() {
            alice.sub_one();
            let mut bob = read_u256(BOB_BASE);
            bob.add_one();
            write_u256(ALICE_BASE, alice);
            write_u256(BOB_BASE, bob);
        }
        read_u128(BOB_BASE) as i64
    }
}
