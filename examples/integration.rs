use memflow::architecture::x86::*;
use memflow::prelude::{ErrorKind, Result, *};
use memflow_linux::kernel::x64::{find_kernel, KernelInfo};

use clap::*;
use log::Level;

fn main() -> Result<()> {
    let (conn, args, level, print_kallsyms) = parse_args()?;

    simple_logger::SimpleLogger::new()
        .with_level(level.to_level_filter())
        .init()
        .unwrap();

    let inventory = Inventory::scan();

    let mut connector = inventory.create_connector(&conn, None, &args)?;

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

    if print_kallsyms {
        let time = std::time::Instant::now();

        for (addr, name) in kallsyms.syms_iter(&mut mem) {
            println!("{:016x} {}", addr.as_u64(), name);
        }

        println!("Elapsed: {}", time.elapsed().as_secs_f32());
    }

    Ok(())
}

fn parse_args() -> Result<(String, Args, log::Level, bool)> {
    let matches = App::new("linux integration example")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("verbose").short("v").multiple(true))
        .arg(
            Arg::with_name("connector")
                .long("connector")
                .short("c")
                .takes_value(true)
                .default_value("kcore")
                .required(false),
        )
        .arg(
            Arg::with_name("conn-args")
                .long("conn-args")
                .short("x")
                .takes_value(true)
                .default_value(""),
        )
        .arg(
            Arg::with_name("kallsyms")
                .long("kallsyms")
                .short("k")
                .required(false),
        )
        .get_matches();

    // set log level
    let level = match matches.occurrences_of("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        4 => Level::Trace,
        _ => Level::Trace,
    };

    Ok((
        matches.value_of("connector").unwrap_or("").into(),
        Args::parse(matches.value_of("conn-args").ok_or_else(|| {
            Error(ErrorOrigin::Other, ErrorKind::Configuration)
                .log_error("failed to parse connector args")
        })?)?,
        level,
        matches.occurrences_of("kallsyms") > 0,
    ))
}
