# pkcs11-module

Find a PKCS#11 provider's exported interfaces without calling `C_Initialize`.

This crate resolves `C_GetFunctionList`, enumerates `C_GetInterfaceList` and
reexports the layout APIs from `pkcs11-abi`. It is part of the
[pkcs11-components](https://github.com/mingulov/pkcs11-components) workspace.

```toml
[dependencies]
pkcs11-module = "0.2"
libloading = "0.8" # needed when your code opens provider libraries
```

```rust,no_run
let library = unsafe { libloading::Library::new("/path/to/provider.so") }
    .expect("trusted provider should load");
let table = pkcs11_module::function_list(&library)
    .expect("provider should export a valid C_GetFunctionList");
println!("legacy function table: {table:p}");
```

Loading a shared library executes foreign initialization code. Keep `library`
alive for as long as any returned pointer may be used.

## Features

The default `native` feature enables provider acquisition. Without it, the
crate is a `no_std` wrapper around `pkcs11-abi` with no other dependencies.
Only the target-layout APIs are available in that build.

With `native`, the `params` module and native parameter types are reexported
from `pkcs11-abi`, including corrected MQV pointer names and the proposed
external-mu definitions. Check the provider for support before using them.

See the [workspace README](https://github.com/mingulov/pkcs11-components)
for usage, safety requirements and versioning.

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
