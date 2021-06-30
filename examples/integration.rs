use memflow::architecture::x86::*;
use memflow::prelude::*;
use memflow_linux::{find_kernel, KernelInfo};

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

    let inventory = Inventory::scan();

    let mut connector = inventory.create_connector("kcore", None, &Args::default())?;

    let KernelInfo {
        cr3,
        virt_text,
        kallsyms,
        ..
    } = find_kernel(connector.forward_mut())?;

    let connector = CachedMemoryAccess::builder(connector)
        .arch(x64::ARCH)
        .build()?;

    println!("Kernel virt text: {:x}", virt_text);

    let x64_translator = x64::new_translator(cr3);

    let vat = DirectTranslate::new();

    let vat = CachedVirtualTranslate::builder(vat)
        .arch(x64::ARCH)
        .build()?;

    let mut mem = VirtualDma::with_vat(connector, x64::ARCH, x64_translator, vat);

    println!("num syms: {}", kallsyms.num_syms());

    let time = std::time::Instant::now();

    for (addr, name) in kallsyms.syms_iter(&mut mem) {
        println!("{:016x} {}", addr.as_u64(), name);
    }

    println!("Elapsed: {}", time.elapsed().as_secs_f32());

    Ok(())
}
