use memflow::prelude::*;
use std::convert::TryInto;

use memflow::architecture::x86::x64;

use iced_x86::*;

pub mod kallsyms;
use kallsyms::KallsymsInfo;

#[derive(Clone, Copy)]
pub struct KernelInfo {
    pub cr3: Address,
    pub phys_base: Address,
    pub la57_on: bool,
    pub virt_text: Address,
    pub phys_text: Address,
    pub kallsyms: KallsymsInfo,
}

fn find_kallsyms(
    mem: &mut impl PhysicalMemory,
    cr3: Address,
    virt_text: Address,
) -> Result<KallsymsInfo> {
    let mut buf = vec![0; size::mb(2)];

    let x64_translator = x64::new_translator(cr3);

    let mut mem = VirtualDma::new(mem.forward(), x64::ARCH, x64_translator);

    mem.virt_read_raw_into(virt_text, &mut buf)?;

    let kallsyms_lookup = find_kallsyms_lookup(&mut mem, &buf, virt_text)?;

    println!("kallsyms_lookup: {:x}", kallsyms_lookup);

    let (kallsyms_expand_symbol, _) = find_kallsyms_expand_symbol(
        &mut mem,
        &buf[(kallsyms_lookup - virt_text)..],
        kallsyms_lookup,
    )?;

    println!("kallsyms_expand_symbol: {:x}", kallsyms_expand_symbol);

    let (kallsyms_names, token_index, token_table) =
        parse_expand_symbol(kallsyms_expand_symbol, &mut mem, &mut buf[0..size::kb(4)])?;

    let kallsyms = KallsymsInfo::new(
        kallsyms_expand_symbol,
        kallsyms_names,
        token_table,
        token_index,
        8,
        &mut mem,
    )?;

    println!("{:#?}", kallsyms);

    Ok(kallsyms)

    /*kallsyms.expand_symbol = kallsyms_expand_symbol;

    kallsyms = parse_expand_symbol(kallsyms, &mut mem, &mut buf[0..size::kb(4)])?;

    // -alignment, which is 8 in x64
    kallsyms.num_syms = kallsyms.names - 8;

    Ok(kallsyms)*/
}

fn find_kallsyms_lookup(
    mem: &mut impl VirtualMemory,
    buf: &[u8],
    virt_text: Address,
) -> Result<Address> {
    let mut prev_call = None;

    let mut decoder = Decoder::new(64, &buf, DecoderOptions::NONE);

    decoder.set_ip(virt_text.as_u64());

    // Walk down the buffer and find a function that contains target format string.
    for instr in decoder.into_iter() {
        if instr.is_call_near() && prev_call.is_none() {
            // Save the first call instruction in the function, that's where kallsyms_lookup should be.
            prev_call = Some(Address::from(instr.near_branch_target()));
        } else if instr.mnemonic() == Mnemonic::Push && instr.op0_register() == Register::R14 {
            // Reset the prev_call if we reach push of R14, basically start of the function.
            prev_call = None;
        } else if instr.mnemonic() == Mnemonic::Mov {
            // The target string is inside an immediate32to64 value.
            if let Ok(OpKind::Immediate32to64) = instr.try_op_kind(1) {
                let target = Address::from(instr.immediate32to64() as u64);
                let target_str = "+%#lx/%#lx";
                if let Ok(read_str) = mem.virt_read_char_array(target, target_str.len() + 1) {
                    if read_str.starts_with(target_str) {
                        return Ok(prev_call.unwrap());
                    }
                }
            }
        }
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
}

fn is_kallsyms_expand_symbol(mem: &mut impl VirtualMemory, address: Address) -> Result<Address> {
    let mut buf = vec![0; size::kb(4)];

    mem.virt_read_raw_into(address, &mut buf).data_part()?;

    let mut decoder = Decoder::new(64, &buf, DecoderOptions::NONE);

    decoder.set_ip(address.as_u64());

    let mut formatter = NasmFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_first_operand_char_index(10);
    formatter.options_mut().set_uppercase_all(false);
    formatter.options_mut().set_uppercase_hex(false);

    let mut output = String::new();

    println!("Disasm {:x}", address);

    let mut prev_displacement = 0;

    for instr in decoder.into_iter() {
        output.clear();
        formatter.format(&instr, &mut output);

        println!("{:x}: {}", instr.ip(), output);

        // The unique signature are 2 moves that have the same address,
        // followed by another move that is one higher from the previous one.
        // Match both of them.
        if instr.memory_base() == Register::RAX {
            let displacement = instr.memory_displacement64();
            if displacement != 0
                && (displacement == prev_displacement
                    || displacement == prev_displacement.saturating_add(1))
            {
                return Ok(prev_displacement.into());
            }
            prev_displacement = displacement;
        }

        if instr.mnemonic() == Mnemonic::Ret {
            break;
        }

        // kallsyms_expand_symbol has no branches before the unique signature
        if instr.near_branch_target() != 0 {
            break;
        }
    }

    Err(ErrorOrigin::OsLayer.into())
}

fn find_kallsyms_expand_symbol(
    mem: &mut impl VirtualMemory,
    buf: &[u8],
    kallsyms_lookup: Address,
) -> Result<(Address, Address)> {
    let mut decoder = Decoder::new(64, &buf, DecoderOptions::NONE);

    decoder.set_ip(kallsyms_lookup.as_u64());

    let mut furthest_jump = 0;

    for instr in decoder.into_iter() {
        if instr.mnemonic() == Mnemonic::Ret && instr.ip() >= furthest_jump {
            break;
        }

        if instr.is_call_near() {
            if let Ok(addr) = is_kallsyms_expand_symbol(mem, instr.near_branch_target().into()) {
                return Ok((instr.near_branch_target().into(), addr));
            }
        } else if instr.near_branch_target() > instr.ip() && instr.mnemonic() != Mnemonic::Jmp {
            furthest_jump = std::cmp::max(furthest_jump, instr.near_branch_target());
        } else if instr.mnemonic() == Mnemonic::Jmp {
            break;
        }
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
}

fn parse_expand_symbol(
    expand_symbol: Address,
    mem: &mut impl VirtualMemory,
    buf: &mut [u8],
) -> Result<(Address, Address, Address)> {
    mem.virt_read_raw_into(expand_symbol, buf)?;

    let mut decoder = Decoder::new(64, &buf, DecoderOptions::NONE);

    decoder.set_ip(expand_symbol.as_u64());

    let mut formatter = NasmFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_first_operand_char_index(10);
    formatter.options_mut().set_uppercase_all(false);
    formatter.options_mut().set_uppercase_hex(false);

    let mut output = String::new();

    let mut prev_displacement = Address::null();

    // First phase, extract the `kallsyms_names` variable
    let names = loop {
        if !decoder.can_decode() {
            break None;
        }

        let instr = decoder.decode();
        output.clear();
        formatter.format(&instr, &mut output);

        println!("{:x}: {}", instr.ip(), output);

        // The unique signature are 2 moves that have the same address,
        // followed by another move that is one higher from the previous one.
        // Match both of them.
        if instr.memory_base() == Register::RAX {
            let displacement = instr.memory_displacement64().into();
            if displacement != Address::NULL
                && (displacement == prev_displacement || displacement == prev_displacement + 1)
            {
                break Some(displacement);
            }
            prev_displacement = displacement;
        }

        if instr.mnemonic() == Mnemonic::Ret {
            break None;
        }

        // kallsyms_expand_symbol has no branches before the unique signature
        if instr.near_branch_target() != 0 {
            break None;
        }
    }
    .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))?;

    println!("Found names: {}", names);

    // Second phase, find the token index table.
    let token_index = loop {
        if !decoder.can_decode() {
            break None;
        }

        let instr = decoder.decode();
        output.clear();
        formatter.format(&instr, &mut output);

        println!("{:x}: {}", instr.ip(), output);

        if instr.memory_base() == Register::RAX {
            let displacement: Address = instr.memory_displacement64().into();
            if (displacement.as_u64() as i64) < 0
                && (displacement != prev_displacement && displacement != prev_displacement + 1)
            {
                break Some(displacement);
            }
            prev_displacement = displacement;
        }

        if instr.mnemonic() == Mnemonic::Ret {
            break None;
        }
    }
    .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))?;

    println!("Found token index: {}", token_index);

    let token_table = loop {
        if !decoder.can_decode() {
            break None;
        }

        let instr = decoder.decode();
        output.clear();
        formatter.format(&instr, &mut output);

        println!("{:x}: {}", instr.ip(), output);

        // This usually is in RDX register, but that could be different on other compilers
        let displacement: Address = instr.memory_displacement64().into();
        if (displacement.as_u64() as i64) < 0 && displacement != prev_displacement {
            break Some(displacement);
        }
        prev_displacement = displacement;

        if instr.mnemonic() == Mnemonic::Ret {
            break None;
        }
    }
    .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))?;

    println!("Found token table: {}", token_table);

    Ok((names, token_index, token_table))
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

pub fn find_kernel_base(
    mem: &mut impl PhysicalMemory,
    cr3: Address,
    text_base: Address,
) -> Result<Address> {
    let x64_translator = x64::new_translator(cr3);

    let mut mem = VirtualDma::new(mem.forward(), x64::ARCH, x64_translator);

    mem.phys_to_virt(text_base)
        .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
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

pub fn find_kernel(mut mem: impl PhysicalMemory) -> Result<KernelInfo> {
    let metadata = mem.metadata();

    let mut buf = vec![0; size::mb(2)];

    let page_size = size::kb(4);
    let page_align = size::mb(2);
    let buf_range = buf.len() * page_align / page_size;

    let mut read_data = buf
        .chunks_mut(page_size)
        .map(|chunk| PhysicalReadData(PhysicalAddress::INVALID, chunk.into()))
        .collect::<Vec<_>>();

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

    for addr in (0..metadata.size).step_by(buf_range).map(Address::from) {
        for (i, PhysicalReadData(paddr, buf)) in read_data.iter_mut().enumerate() {
            *paddr = Address::from(addr + i * page_align).into();
            buf.iter_mut().for_each(|i| *i = 0);
        }

        mem.phys_read_raw_list(read_data.as_mut_slice())?;

        println!("READ {:x}", addr);

        for (addr, num) in read_data
            .iter()
            .flat_map(|PhysicalReadData(paddr, buf)| {
                let addr = paddr.address();
                buf.windows(bytes.len())
                    .enumerate()
                    .map(move |(off, w)| (addr + off, w))
            })
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
            let text_base = addr.as_page_aligned(size::mb(2));

            if cr3 != phys_base && cr3 < metadata.size as u64 {
                println!("phys_base: {:x}", phys_base);
                println!("CR3: {:x}", cr3);
                println!("LA57 ON: {:x}", la57);
                println!("phys text: {:x}", text_base);

                let virt_text = find_kernel_base(&mut mem, cr3.into(), text_base)?;

                let kallsyms = find_kallsyms(&mut mem, cr3.into(), virt_text)?;

                return Ok(KernelInfo {
                    cr3: cr3.into(),
                    la57_on: la57 != 0,
                    phys_base: phys_base.into(),
                    phys_text: text_base,
                    virt_text,
                    kallsyms,
                });
            }
        }
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
}
