use pkcs11_abi::{LinuxLayout, function_name, table_bytes};

fn main() {
    // PKCS#11 3.2 adds fields through ordinal 103, for 104 fields total.
    // An ILP32 table begins with a two-byte CK_VERSION plus two bytes of
    // alignment padding, followed by 104 four-byte function pointers:
    // 4 + (104 * 4) = 420 bytes.
    let bytes = table_bytes(LinuxLayout::Ilp32, 104).expect("known table size");
    println!(
        "PKCS#11 3.2 ILP32 prefix: {bytes} bytes; final field: {}",
        function_name(103).unwrap()
    );
}
