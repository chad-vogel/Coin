unsafe extern "C" {
    fn get(key: i32) -> i64;
    fn set(key: i32, value: i64);
}

pub unsafe extern "C" fn contract_main() -> i64 {
    unsafe {
        let v = get(0);
        set(0, v + 1);
        get(0)
    }
}

fn main() {}
