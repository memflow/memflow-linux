use memflow::prelude::*;
use memflow_linux::find_kernel;

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Trace)
        .init()
        .unwrap();

    let inventory = Inventory::scan();

    let connector = inventory.create_connector("kcore", None, &Args::default())?;

    find_kernel(connector, Some(0x2e0000000u64.into()))?;

    Ok(())
}
