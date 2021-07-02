use memflow::prelude::v1::*;

#[derive(Clone, Copy, Debug)]
pub struct KallsymsInfo {
    // Kallsyms has a predictable data layout.
    //
    // The fields are laid out in the order given below.
    // Some fields and their functions differ based on the
    // config parameters for the kernel.
    //
    // Absolute addresses are rarely used,
    // require !CONFIG_KALLSYMS_BASE_RELATIVE
    //pub addresses: Address,
    offsets: Address,
    relative_base: Address,
    num_syms: usize,
    names: Address,
    markers: Address,
    token_table: Address,
    token_index: Address,

    expand_symbol: Address,
}

impl KallsymsInfo {
    pub fn new(
        expand_symbol: Address,
        names: Address,
        token_table: Address,
        token_index: Address,
        alignment: usize,
        mem: &mut impl VirtualMemory,
    ) -> Result<Self> {
        // Walk down from the names
        let num_syms_addr = (names - 4).as_page_aligned(alignment);
        let num_syms = mem.virt_read::<i32>(num_syms_addr)? as usize;
        let relative_base_addr = (num_syms_addr - 8).as_page_aligned(alignment);
        let relative_base = mem.virt_read::<u64>(relative_base_addr)?.into();
        let offsets = (relative_base_addr - num_syms * 4).as_page_aligned(alignment);

        // TODO: fallback walk names, if token_index is null, and token_table

        let num_markers = (num_syms + 255) >> 8;

        let markers = (token_table - num_markers * 4).as_page_aligned(alignment);

        //let token_table = (markers + num_markers * 4 + (alignment - 1)).as_page_aligned(alignment);
        //let token_index = (token_table + size::kb(64) + (alignment - 1)).as_page_aligned(alignment);

        Ok(Self {
            offsets,
            relative_base,
            num_syms,
            names,
            markers,
            token_table,
            token_index,
            expand_symbol,
        })
    }

    pub fn num_syms(&self) -> usize {
        self.num_syms
    }

    pub fn expand_symbol(
        &self,
        mem: &mut impl VirtualMemory,
        offset: usize,
        name: &mut String,
    ) -> Result<usize> {
        name.clear();

        let len = mem.virt_read::<u8>(self.names + offset)?;

        for i in 1..=len {
            let byte = mem.virt_read::<u8>(self.names + offset + i as usize)?;
            let idx = mem.virt_read::<u16>(self.token_index + byte as usize * 2)?;
            let s = mem.virt_read_char_string(self.token_table + idx as usize)?;

            name.extend(s.chars().skip(if i == 1 { 1 } else { 0 }));
        }

        Ok(offset + len as usize + 1)
    }

    // This function is used when both CONFIG_KALLSYMS_BASE_RELATIVE and
    // CONFIG_KALLSYMS_ABSOLUTE_PERCPU are set.
    pub fn sym_address(&self, mem: &mut impl VirtualMemory, idx: usize) -> Result<Address> {
        let offset = mem.virt_read::<i32>(self.offsets + idx * 4)?;

        if offset < 0 {
            Ok(self.relative_base - 1 + (-offset) as usize)
        } else {
            Ok(Address::from(offset as u64))
        }
    }

    pub fn syms_iter<'a, T: VirtualMemory>(&'a self, mem: &'a mut T) -> KallsymsIterator<'a, T> {
        KallsymsIterator::new(self, mem)
    }

    /*pub fn lookup_name(&self, sym: &str, mem: &mut impl VirtualMemory) -> Result<Address> {
        Ok(Address::NULL)
    }*/
}

pub struct KallsymsIterator<'a, T> {
    kallsyms: &'a KallsymsInfo,
    mem: &'a mut T,
    cur_idx: usize,
    cur_name_off: usize,
}

impl<'a, T: VirtualMemory> KallsymsIterator<'a, T> {
    pub fn new(kallsyms: &'a KallsymsInfo, mem: &'a mut T) -> Self {
        Self {
            kallsyms,
            mem,
            cur_idx: 0,
            cur_name_off: 0,
        }
    }

    pub fn next_allocfree(&mut self, out_name: &mut String) -> Option<Address> {
        if self.cur_idx >= self.kallsyms.num_syms {
            return None;
        }

        out_name.clear();

        let address = self.kallsyms.sym_address(self.mem, self.cur_idx).ok()?;

        self.cur_name_off = self
            .kallsyms
            .expand_symbol(self.mem, self.cur_name_off, out_name)
            .ok()?;

        self.cur_idx += 1;

        Some(address)
    }
}

impl<'a, T: VirtualMemory> Iterator for KallsymsIterator<'a, T> {
    type Item = (Address, String);

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur_idx >= self.kallsyms.num_syms {
            return None;
        }

        let mut name = String::new();

        let address = self.next_allocfree(&mut name)?;

        Some((address, name))
    }
}
