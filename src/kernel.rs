use memflow::prelude::v1::*;

pub mod x64;

pub struct Kernel<Mem, Info> {
    mem: Mem,
    info: Info,
    offsets: KernelOffsets,
}

#[derive(Clone, Copy)]
pub struct KernelOffsets {
    init_task: Address,
    task_offsets: TaskOffsets,
    mm_offsets: MmStructOffsets,
}

#[derive(Clone, Copy)]
pub struct TaskOffsets {
    // machine_power_off, but requires following several references
    // clear_tasks_mm_cpumask
    // walk_process_tree (alternative, not the real thing)
    pub tasks: usize,
    pub mm: usize,
    pub active_mm: usize,
}

#[derive(Clone, Copy)]
pub struct MmStructOffsets {
    pub pgd: usize,
    // vdso?
}
