fn main() -> Result<(), String> {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: inspect /absolute/path/to/provider.so");
        return Ok(());
    };

    // SAFETY: loading a shared library executes its initialization code. Only
    // inspect a provider you trust. Keep this handle alive while using any
    // provider-owned pointer acquired below.
    let library = unsafe { libloading::Library::new(path) }
        .map_err(|error| format!("cannot load provider: {error}"))?;
    let table = pkcs11_module::function_list(&library)?;
    println!("legacy function table: {table:p}");

    match pkcs11_module::interface_list(&library)? {
        None => println!("C_GetInterfaceList: not exported"),
        Some(interfaces) => println!("C_GetInterfaceList: {} interface(s)", interfaces.len()),
    }
    Ok(())
}
