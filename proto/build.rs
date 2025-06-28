fn main() {
    let proto_file = "proto/transaction.proto";
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc not found");
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    prost_build::compile_protos(&[proto_file], &["proto"]).unwrap();
}
