fn main() {
    let proto_file = "proto/transaction.proto";
    prost_build::compile_protos(&[proto_file], &["proto"]).unwrap();
}
