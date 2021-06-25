use memflow::architecture::x86::*;
use memflow::prelude::*;
use memflow_linux::find_kernel;
use reflow::prelude::v1::*;

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

    let inventory = Inventory::scan();

    let mut connector = inventory.create_connector("kcore", None, &Args::default())?;

    let (cr3, text) = find_kernel(connector.forward_mut())?;

    println!("Kernel virt text: {:x}", text);

    let x64_translator = x64::new_translator(cr3);

    let mem = VirtualDma::new(connector, x64::ARCH, x64_translator);

    let mut oven = Oven::new_with_arch(mem, ArchitectureIdent::X86(64, false))
        .stack(Stack::new().ret_addr(0xDEADBEEFu64))
        .params(Parameters::new().reg_str(RegisterX86::RDI, "kallsyms_lookup_name"))
        .entry_point(Address::from(0xffffffffb118c080u64));

    let time = std::time::Instant::now();

    let result = oven.reflow().unwrap();

    println!(
        "result: {:x}",
        result.reg_read_u64(RegisterX86::RAX).unwrap()
    );

    println!("Elapsed: {}", time.elapsed().as_secs_f32());

    Ok(())
}
