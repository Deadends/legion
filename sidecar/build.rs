fn main() {
    // Set OpenSSL paths for Windows during build
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-search=native=C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD");
        println!("cargo:rustc-link-lib=libssl");
        println!("cargo:rustc-link-lib=libcrypto");
        
        // Set environment variables for openssl-sys
        println!("cargo:rustc-env=OPENSSL_DIR=C:\\Program Files\\OpenSSL-Win64");
        println!("cargo:rustc-env=OPENSSL_LIB_DIR=C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD");
        println!("cargo:rustc-env=OPENSSL_INCLUDE_DIR=C:\\Program Files\\OpenSSL-Win64\\include");
        
        // Also set for the build process itself
        std::env::set_var("OPENSSL_DIR", r"C:\Program Files\OpenSSL-Win64");
        std::env::set_var("OPENSSL_LIB_DIR", r"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD");
        std::env::set_var("OPENSSL_INCLUDE_DIR", r"C:\Program Files\OpenSSL-Win64\include");
    }
}