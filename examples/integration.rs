use memflow::architecture::x86::*;
use memflow::prelude::{ErrorKind, Result, *};
use memflow_linux::kernel::x64::{find_kernel, KernelInfo};

use clap::*;
use log::Level;

fn main() -> Result<()> {
    let matches = parse_args();
    let (chain, log_level, print_kallsyms) = extract_args(&matches)?;

    simplelog::TermLogger::init(
        log_level.to_level_filter(),
        simplelog::Config::default(),
        simplelog::TerminalMode::Stdout,
        simplelog::ColorChoice::Auto,
    )
    .unwrap();

    let inventory = Inventory::scan();

    let mut connector = inventory.builder().connector_chain(chain).build()?;

    let KernelInfo {
        cr3,
        virt_text,
        kallsyms,
        ..
    } = find_kernel(connector.forward_mut())?;

    let connector = CachedPhysicalMemory::builder(connector)
        .arch(x64::ARCH)
        .build()?;

    println!("Kernel virt text: {:x}", virt_text);

    println!("Kernel cr3: {:x}", cr3);

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
            println!("{:016x} {}", addr.to_umem(), name);
        }

        println!("Elapsed: {}", time.elapsed().as_secs_f32());
    }

    Ok(())
}

fn parse_args() -> ArgMatches {
    Command::new("linux integration example")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::new("verbose").short('v').action(ArgAction::Count))
        .arg(
            Arg::new("connector")
                .long("connector")
                .short('c')
                .action(ArgAction::Append)
                .required(true),
        )
        .arg(
            Arg::new("os")
                .long("os")
                .short('o')
                .action(ArgAction::Append)
                .required(false),
        )
        .arg(
            Arg::new("kallsyms")
                .long("kallsyms")
                .short('k')
                .action(ArgAction::Count)
                .required(false),
        )
        .get_matches()
}

fn extract_args(matches: &ArgMatches) -> Result<(ConnectorChain<'_>, log::Level, bool)> {
    // set log level
    let level = match matches.get_count("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        4 => Level::Trace,
        _ => Level::Trace,
    };

    let conn_iter = matches
        .indices_of("connector")
        .zip(matches.get_many::<String>("connector"))
        .map(|(a, b)| a.zip(b.map(String::as_str)))
        .into_iter()
        .flatten();

    let os_iter = matches
        .indices_of("os")
        .zip(matches.get_many::<String>("os"))
        .map(|(a, b)| a.zip(b.map(String::as_str)))
        .into_iter()
        .flatten();

    let print_kallsyms = matches.get_count("kallsyms") > 0;

    Ok((
        ConnectorChain::new(conn_iter, os_iter)?,
        level,
        print_kallsyms,
    ))
}
