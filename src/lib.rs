use memflow::prelude::*;
use std::convert::TryInto;

use goblin::Object;

use memflow::architecture::x86::x64;

struct KernelInfo {
    cr3: Address,
    la57_on: bool,
}

fn read_val_at(buf: &[u8], buf_off: usize) -> u32 {
    u32::from_le_bytes(buf[buf_off..(buf_off + 4)].try_into().unwrap())
}

fn read_val_relat<T: dataview::Pod>(
    mem: &mut impl PhysicalMemory,
    buf: &[u8],
    buf_off: usize,
    off: Address,
) -> Result<T> {
    let reloff = read_val_at(buf, buf_off) as usize;
    println!("PR {:x} {:x}", off, reloff + buf_off);
    mem.phys_read((off + reloff + buf_off).into())
}

fn check_va(mem: &mut impl VirtualMemory, addr: Address) -> Result<Address> {
    let mut buf = vec![0; size::mb(2)];

    mem.virt_read_raw_into(addr, &mut buf).data_part()?;

    buf.chunks_exact(x64::ARCH.page_size())
        .enumerate()
        .filter_map(|(i, c)| {
            if let Ok(Object::Elf(elf)) = Object::parse(c) {
                Some((i, c, elf))
            } else {
                None
            }
        })
        .map(|(i, b, c)| (addr + i * x64::ARCH.page_size(), b, c))
        .inspect(|(a, _, obj)| println!("{:x} {:?}", a, obj))
        .map(|(a, _, _)| a)
        .last()
        .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
}

pub fn find_kernel_base(mut mem: impl PhysicalMemory, cr3: Address) -> Result<Address> {
    let x64_translator = x64::new_translator(cr3);

    // This not
    let val = x64_translator.virt_to_phys(&mut mem, 0xffffffff8d000000u64.into());

    println!("TR {:?}", &val);

    println!("{:x}", val.unwrap_or_default());

    println!("DMA");

    let mut mem = VirtualDma::new(mem, x64::ARCH, x64_translator);

    let page_map = mem.virt_page_map(size::mb(2));

    for &(addr, size) in page_map.iter() {
        println!("{:x}-{:x}", addr, addr + size);
    }

    match page_map
        .into_iter()
        .flat_map(|(va, size)| size.page_chunks(va, size::mb(2)))
        .filter(|&(_, size)| size > size::kb(256))
        .filter_map(|(va, _)| check_va(&mut mem, va).ok())
        .next()
    {
        Some(a) => Ok(a),
        None => Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound)),
    }
}

fn str_to_byte_iter<'a>(s: &'a str) -> impl 'a + Iterator<Item = u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap_or(0))
}

fn str_to_mask_iter<'a>(s: &'a str) -> impl 'a + Iterator<Item = u8> {
    s.split_whitespace()
        .map(|b| if b.contains("?") { 0 } else { 0xff })
}

fn str_to_deref_pos_iter<'a>(s: &'a str, off: usize) -> (usize, impl 'a + Iterator<Item = usize>) {
    (
        off + s.split_whitespace().enumerate().count(),
        s.split_whitespace()
            .enumerate()
            .filter(|(_, b)| b.starts_with("*"))
            .map(move |(i, _)| i + off),
    )
}

fn strs_to_sig(s: &[&str]) -> (Vec<u8>, Vec<u8>, Vec<usize>) {
    let mut bytes = vec![];
    let mut mask = vec![];
    let mut deref_pos = vec![];

    let mut off = 0;

    for s in s {
        bytes.extend(str_to_byte_iter(s));
        mask.extend(str_to_mask_iter(s));
        let (o, i) = str_to_deref_pos_iter(s, off);
        off = o;
        deref_pos.extend(i);
    }

    (bytes, mask, deref_pos)
}

pub fn find_kernel(mut mem: impl PhysicalMemory, upper_hint: Option<Address>) -> Result<Address> {
    let metadata = mem.metadata();

    let mut buf = vec![0; size::mb(256)];

    // https://elixir.bootlin.com/linux/v5.9.16/source/arch/x86/kernel/head_64.S#L112

    //let pat = "e8 bb 00 00 00";

    let pat_with_sev = "e8 cb 00 00 00";

    let pat_middle = "56
        e8 ? ? ? ?
        5e
        48 05 *? ? ? ?
        b9 a0 00 00 00
        f7 05 *? ? ? ? 01 00 00 00
        74 06
        81 c9 00 10 00 00
        0f 22 e1
        48 03 05 *? ? ? ?";

    // Was added in 5.10: https://elixir.bootlin.com/linux/v5.10.31/source/arch/x86/kernel/head_64.S#L173
    let pat_sev = "56
        48 89 c7
        e8 ? ? ? ?
        5e";

    let pat_end = "
        0f 22 d8
        48 c7 c0 ? ? ? ?
        ff e0
    ";

    //let (bytes_59, mask_59, deref_pos_59) = strs_to_sig(&[pat, pat_middle, pat_end]);
    let (bytes, mask, deref_pos) = strs_to_sig(&[pat_with_sev, pat_middle, pat_sev, pat_end]);

    let (cr3_off, la57_reloff, phys_base_reloff) = (deref_pos[0], deref_pos[1], deref_pos[2]);

    for addr in (0..upper_hint.map(|x| x.as_usize()).unwrap_or(metadata.size))
        .step_by(buf.len())
        .rev()
        .map(Address::from)
    {
        buf.iter_mut().for_each(|i| *i = 0);
        mem.phys_read_raw_into(addr.into(), buf.as_mut_slice())?;

        println!("READ {:x}", addr);

        for (addr, num) in buf
            .windows(bytes.len())
            .enumerate()
            .map(|(off, w)| (addr + off, w))
            .filter(|(_, w)| {
                w.iter()
                    .zip(&mask)
                    .map(|(b, m)| b & m)
                    .eq(bytes.iter().copied())
            })
        {
            let mut st = String::new();
            for b in num {
                st += &format!("{:02x} ", b);
            }
            println!("MATCH FOUND {:?} {:x}", st, addr);

            let cr3_off = read_val_at(num, cr3_off) as usize;
            let la57 = read_val_relat(&mut mem, num, la57_reloff, addr + 8).unwrap_or(0) & 1;
            let phys_base = read_val_relat(&mut mem, num, phys_base_reloff, addr + 4).unwrap_or(0);
            let cr3 = phys_base + cr3_off as u64;

            if cr3 != phys_base && cr3 < metadata.size as u64 {
                println!("phys_base: {:x}", phys_base);
                println!("CR3: {:x}", cr3);
                println!("LA57 ON: {:x}", la57);
                return find_kernel_base(mem, cr3.into());
            }
        }
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
}
