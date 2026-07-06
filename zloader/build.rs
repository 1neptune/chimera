fn main() {

    println!("cargo:rustc-link-arg=/DEBUG");
    

    #[cfg(target_arch = "x86")]
    {
        println!("cargo:rustc-link-arg=/LARGEADDRESSAWARE");
    }
}