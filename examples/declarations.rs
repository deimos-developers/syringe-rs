//! Build and inspect Syringe hook/host declarations without a game.

use syringe_rs::syringe_api::{HOOKS_SECTION, HookDecl, HostDecl};

fn main() {
    let hook = HookDecl::new(0x004F_4583, 6, 0x1040_0000);
    let host = HostDecl::new(0, 0x1040_0010);

    println!("hooks section: {HOOKS_SECTION}");
    println!(
        "hook addr=0x{:08X}, size={}, name_ptr=0x{:08X}",
        hook.hook_addr, hook.hook_size, hook.hook_name_ptr
    );
    println!(
        "host checksum=0x{:08X}, name_ptr=0x{:08X}",
        host.host_checksum, host.host_name_ptr
    );
    assert!(hook.is_named() && host.is_named());
}
