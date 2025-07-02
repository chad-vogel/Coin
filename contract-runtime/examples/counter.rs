unsafe extern "C" {
    fn get(key: i32) -> i64;
    fn set(key: i32, value: i64);
}

pub extern "C" fn entry() {
    unsafe {
        let v = get(0);
        set(0, v + 1);
    }
}

fn main() {
    entry();
}
