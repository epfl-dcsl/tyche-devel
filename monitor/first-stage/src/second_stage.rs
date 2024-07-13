//! Second-Stage

use alloc::vec::Vec;
use core::arch::asm;
use core::cmp::min;
use core::sync::atomic::{AtomicBool, Ordering};
use core::{mem, slice};

use bootloader::boot_info::MemoryRegionKind;
use mmu::frame_allocator::PhysRange;
use mmu::ioptmapper::PAGE_MASK;
use mmu::memory_coloring::color_to_phys::{
    MemoryRegion as S2MemRegion, MemoryRegionKind as S2MemoryRegionKind,
};
use mmu::memory_coloring::{MemoryColoring, MemoryRange};
use mmu::walker::Address;
use mmu::{PtFlag, PtMapper, RangeAllocator};
use stage_two_abi::{EntryPoint, Manifest, Smp};
use x86_64::{align_down, align_up, VirtAddr};

use crate::cpu::MAX_CPU_NUM;
use crate::elf::relocate::relocate_elf;
use crate::elf::{ELfTargetEnvironment, Elf64PhdrType, ElfProgram, NonContigElf64Phdr};
use crate::guests::ManifestInfo;
use crate::mmu::frames::{MemoryPartition, PartitionedMemoryMap};
use crate::mmu::PAGE_SIZE;
use crate::{cpu, println, HostPhysAddr, HostVirtAddr};

#[cfg(feature = "second-stage")]
const SECOND_STAGE: &'static [u8] =
    include_bytes!("../../../target/x86_64-unknown-kernel/release/tyche");
#[cfg(not(feature = "second-stage"))]
const SECOND_STAGE: &'static [u8] = &[0; 10];

/// Size of memory allocated by the second stage.
pub const SECOND_STAGE_SIZE: usize = 0x1000 * 2048;
/// Virtual address to which the guest is loaded. Defined by our linker script.
const LOAD_VIRT_ADDR: HostVirtAddr = HostVirtAddr::new(0x80000000000);
//  Stack definitions
const STACK_VIRT_ADDR: HostVirtAddr = HostVirtAddr::new(0x90000000000);
const STACK_SIZE: usize = 0x1000 * 5;

/// Second stage jump structures
static mut SECOND_STAGE_ENTRIES: [Option<Stage2>; MAX_CPU_NUM] = [None; MAX_CPU_NUM];

#[derive(Clone, Copy)]
pub struct Stage2 {
    entry_point: EntryPoint,
    entry_barrier: *mut bool,
    stack_addr: u64,
}

impl Stage2 {
    /// Hands over control to stage 2.
    pub fn jump_into(self) -> ! {
        unsafe {
            asm! {
                "mov rsp, {rsp}",      // Setupt stack pointer
                "call {entry_point}",  // Enter stage 2
                rsp = in(reg) self.stack_addr,
                entry_point = in(reg) self.entry_point,
            }
        }
        panic!("Failed entry or unexpected return from second stage");
    }

    /// Checks if the entry barrier is marked as ready, consume the barrier if ready.
    /// APs must wait for the barier to be marked as ready before jumping into sage 2.
    fn barrier_is_ready(&self) -> bool {
        // Safety: the entry barrier is assumes to point to an atomic bool in stage 2 by
        // construction.
        unsafe {
            let ptr = AtomicBool::from_mut(&mut *self.entry_barrier);
            match ptr.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => true,
                Err(_) => false,
            }
        }
    }
}

/// Enter stage 2.
pub unsafe fn enter() {
    _enter_inner();
}

fn _enter_inner() {
    let cpu_id = cpu::id();
    // Safety:
    let info = unsafe {
        match SECOND_STAGE_ENTRIES[cpu_id] {
            Some(info) => info,
            None => panic!("Tries to jump into stage 2 before initialisation"),
        }
    };

    // BSP do not wait for the barrier
    if cpu_id == 0 {
        info.jump_into();
    } else {
        loop {
            if info.barrier_is_ready() {
                info.jump_into();
            }
            core::hint::spin_loop();
        }
    }
}

pub fn load<T: MemoryColoring + Clone>(
    info: &ManifestInfo,
    stage1_allocator: &impl RangeAllocator,
    stage2_allocator: &impl RangeAllocator,
    pt_mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
    smp: Smp,
    memory_partitions: &PartitionedMemoryMap<T>,
) {
    // Read elf and allocate second stage memory

    //parse elf binary
    let mut second_stage = ElfProgram::new(SECOND_STAGE);
    //TODO: luca: make configurable
    second_stage.set_mapping(crate::elf::ElfMapping::Scattered);

    //this allocates memory for every elf segment. Currently it allocates one physical contiguous chunk
    //the elf headers are updated to point to these memory addresses (in contrast to the default addresses, this is the "relocate" part)
    relocate_elf(&mut second_stage, stage2_allocator, false);
    log::info!("relocated_elf for stage2 segments done;");
    //load parsed elf binary into memory
    let mut stage2_loaded_elf = second_stage
        .load(
            stage2_allocator,
            stage1_allocator.get_physical_offset().as_usize(),
            false,
        )
        .expect("Failed to load second stage");

    log::info!("loading + mapping for stage2 binary done");

    let smp_cores = cpu::cores();
    let smp_stacks: Vec<(HostVirtAddr, HostVirtAddr, HostPhysAddr)> = (0..smp_cores)
        .map(|cpuid| {
            let stack_virt_addr = STACK_VIRT_ADDR + STACK_SIZE * cpuid;
            let (rsp, stack_phys_addr) = stage2_loaded_elf.add_stack(
                VirtAddr::new(stack_virt_addr.as_u64()),
                STACK_SIZE,
                stage2_allocator,
            );
            (
                stack_virt_addr,
                HostVirtAddr::from_u64(rsp.as_u64()),
                HostPhysAddr::from_u64(stack_phys_addr.as_u64()),
            )
        })
        .collect();

    // If we have IOMMU, map it to tyche
    let stage2_iommu_hva;
    let iommu_hpa;
    if let Some(iommu) = info.iommu {
        // Map I/O MMU page, using one to one mapping
        log::info!(
            "Mapping IOMMU to Tyche at HVA 0x{:013x}",
            iommu.base_address.as_u64(),
        );
        stage2_iommu_hva = HostVirtAddr::new(iommu.base_address.as_usize());
        iommu_hpa = iommu.base_address;
        match &mut stage2_loaded_elf.pt_mapper {
            crate::elf::ELfTargetEnvironment::Host(host_mapper) => host_mapper.map_range(
                stage2_allocator,
                stage2_iommu_hva,
                iommu.base_address,
                iommu.size,
                PtFlag::PRESENT | PtFlag::WRITE,
            ),
            crate::elf::ELfTargetEnvironment::Guest(_) => panic!("stage2 with guest mapper"),
        }
    } else {
        stage2_iommu_hva = HostVirtAddr::new(0);
        iommu_hpa = HostPhysAddr::new(0);
    }

    // Map the guest (e.g. linux) memory into Tyche.
    // This is required for hashing content and writing back attestation into Linux-controlled
    // buffers.
    // The amount of ranges required for the guest might be quite large. Thus, storing
    // them in a vec often depletes our heap. Instead, we directly process them in the callback
    let map_guest_phys_range_cb = |pr: PhysRange| match &mut stage2_loaded_elf.pt_mapper {
        crate::elf::ELfTargetEnvironment::Host(host_mapper) => host_mapper.map_range(
            stage2_allocator,
            HostVirtAddr::new(pr.start.as_usize()),
            pr.start,
            pr.size(),
            PtFlag::PRESENT | PtFlag::WRITE,
        ),
        crate::elf::ELfTargetEnvironment::Guest(_) => panic!("stage2 with guest mapper"),
    };
    memory_partitions
        .iterate_over_ranges_for_mem_partition(MemoryPartition::GUEST, map_guest_phys_range_cb);

    // map the default APIC page to 2nd stage
    // TODO aghosn: do we need to hide this?

    let lapic_phys_address: usize = 0xfee00000;
    match &mut stage2_loaded_elf.pt_mapper {
        crate::elf::ELfTargetEnvironment::Host(host_mapper) => host_mapper.map_range(
            stage2_allocator,
            HostVirtAddr::new(lapic_phys_address),
            HostPhysAddr::new(lapic_phys_address),
            PAGE_SIZE,
            PtFlag::PRESENT
                | PtFlag::WRITE
                | PtFlag::PAGE_WRITE_THROUGH
                | PtFlag::PAGE_CACHE_DISABLE,
        ),
        crate::elf::ELfTargetEnvironment::Guest(_) => panic!("stage2 with guest mapper"),
    };

    // If we setup VGA support
    if info.vga_info.is_valid {
        let vga_virt = HostVirtAddr::new(info.vga_info.framebuffer as usize);
        let vga_phys = pt_mapper
            .translate(vga_virt)
            .expect("Failed to translate VGA virt addr");
        log::info!(
            "VGA virt: 0x{:x} - phys: 0x{:x}",
            vga_virt.as_usize(),
            vga_phys.as_usize()
        );
        match &mut stage2_loaded_elf.pt_mapper {
            crate::elf::ELfTargetEnvironment::Host(host_mapper) => host_mapper.map_range(
                stage2_allocator,
                vga_virt,
                vga_phys,
                info.vga_info.len,
                PtFlag::PRESENT | PtFlag::WRITE,
            ),
            crate::elf::ELfTargetEnvironment::Guest(_) => panic!("stage2 with guest mapper"),
        };
    }

    // Map stage 2 into stage 1 page tables
    let stage1_vaddr_for_stage2 = LOAD_VIRT_ADDR.as_usize();
    assert_eq!(stage1_vaddr_for_stage2 % PAGE_SIZE, 0);
    let mut first_stage2_load_paddr = None;
    for seg in &second_stage.segments {
        if seg.phdr.p_type != Elf64PhdrType::PT_LOAD.bits() {
            // Skip non-load segments.
            continue;
        }
        unsafe {
            second_stage.map_segment(
                seg,
                &mut ELfTargetEnvironment::Host(pt_mapper.clone()),
                stage1_allocator,
            )
        };
        if first_stage2_load_paddr.is_none() {
            first_stage2_load_paddr = Some(seg.phys_mem[0].start)
        }
    }

    // Map the MP wakeup mailbox page into stage 2
    match &mut stage2_loaded_elf.pt_mapper {
        crate::elf::ELfTargetEnvironment::Host(host_mapper) => host_mapper.map_range(
            stage2_allocator,
            HostVirtAddr::new(smp.mailbox as usize),
            HostPhysAddr::new(smp.mailbox as usize),
            0x1000,
            PtFlag::PRESENT | PtFlag::WRITE,
        ),
        crate::elf::ELfTargetEnvironment::Guest(_) => panic!("stage2 with guest mapper"),
    };

    smp_stacks
        .iter()
        .for_each(|&(stack_virt_addr, _, stack_phys_addr)| {
            pt_mapper.map_range(
                stage1_allocator,
                stack_virt_addr,
                stack_phys_addr,
                STACK_SIZE,
                PtFlag::PRESENT | PtFlag::WRITE,
            );
        });

    unsafe {
        // Flush TLB
        asm!(
            "mov {tmp}, cr3",
            "mov cr3, {tmp}",
            tmp = out(reg) _,
        );
    }

    // Locate and fill manifest
    let find_symbol = |symbol: &str| {
        second_stage
            .find_symbol(symbol)
            .map(|symbol| symbol.st_value as usize)
    };

    //this is picked up by stage2 in monitor/tyche/src/x86_64/init.rs
    let manifest =
        unsafe { Manifest::from_symbol_finder(find_symbol).expect("Missing symbol in stage 2") };
    let entry_barrier = {
        let ptr = find_symbol("__entry_barrier").expect("Could not find symbol __entry_barrier");
        ptr as *mut bool
    };

    match stage2_loaded_elf.pt_mapper {
        crate::elf::ELfTargetEnvironment::Host(host_mapper) => {
            manifest.cr3 = host_mapper.get_pt_root().as_u64()
        }
        crate::elf::ELfTargetEnvironment::Guest(_) => panic!("stage2_laoded elf used guest mapper"),
    }
    //manifest.cr3 = stage2_loaded_elf.pt_root_spa.as_u64();
    println!("setting manifset.cr3 to 0x{:x}", manifest.cr3);
    manifest.info = info.guest_info.clone();

    manifest.iommu_hva = stage2_iommu_hva.as_u64();
    manifest.iommu_hpa = iommu_hpa.as_u64();

    manifest.poffset = first_stage2_load_paddr
        .expect("first_stage2_load_paddr is uninitialized")
        .as_u64();
    manifest.voffset = LOAD_VIRT_ADDR.as_u64();
    log::info!(
        "manifset.poffset = 0x{:x}, manifset.voffset = 0x{:x}",
        manifest.poffset,
        manifest.voffset
    );
    manifest.vga = info.vga_info.clone();
    manifest.smp = smp;

    manifest.dom0_memory = memory_partitions.guest;
    manifest.remaining_dom_memory = memory_partitions.unused;

    //Copy Memory region to stage2 representation in manifset
    let manifest_s2_mem_regions: &mut [S2MemRegion] = unsafe {
        let len = manifest.raw_mem_regions_slice.len() / mem::size_of::<S2MemRegion>();
        slice::from_raw_parts_mut(
            manifest.raw_mem_regions_slice.as_mut_ptr() as *mut S2MemRegion,
            len,
        )
    };
    //manifest_s2 len is the capacity, i.e. the max amount of entries that this slice can store
    // `raw_mem_regions_slice_valid_entries` tracks the number of valid entries
    assert!(memory_partitions.get_boot_memory_regions().len() <= manifest_s2_mem_regions.len());
    let mut next_boot_mr_idx = 0;
    for boot_mr in memory_partitions.get_boot_memory_regions().iter() {
        /*log::info!(
            "handing over memregion start 0x{:x}, end 0x{:x}",
            boot_mr.start,
            boot_mr.end
        );*/
        manifest_s2_mem_regions[next_boot_mr_idx] = S2MemRegion {
            start: boot_mr.start,
            end: boot_mr.end,
            kind: match boot_mr.kind {
                MemoryRegionKind::Usable => S2MemoryRegionKind::UseableRAM,
                //TODO: this does not really exist anymore, because we carve from last memory region instead of marking in unused
                MemoryRegionKind::UnknownBios(42) => S2MemoryRegionKind::UsedByStage1Allocator,
                MemoryRegionKind::Bootloader
                | MemoryRegionKind::UnknownUefi(_)
                | MemoryRegionKind::UnknownBios(_) => S2MemoryRegionKind::Reserved,
                _ => todo!(),
            },
        };
        next_boot_mr_idx += 1;
    }
    let stage1_mem_range = match memory_partitions.stage1 {
        MemoryRange::ColoredRange(_) => todo!("should not happend"),
        MemoryRange::PhysContigRange(pcr) => pcr,
    };
    manifest_s2_mem_regions[next_boot_mr_idx] = S2MemRegion {
        start: stage1_mem_range.start.as_u64(),
        end: stage1_mem_range.end.as_u64(),
        kind: S2MemoryRegionKind::Reserved,
    };
    next_boot_mr_idx += 1;
    manifest.raw_mem_regions_slice_valid_entries = next_boot_mr_idx;

    debug::hook_stage2_offsets(manifest.poffset, manifest.voffset);
    debug::tyche_hook_stage1(1);

    // Setup second stage jump structure
    unsafe {
        // We need to manually ensure that the type corresponds to the second stage entry point
        // function.
        let entry_point: EntryPoint = core::mem::transmute(second_stage.entry.as_usize());

        smp_stacks
            .iter()
            .enumerate()
            .for_each(|(cpu_id, &(_, rsp, _))| {
                SECOND_STAGE_ENTRIES[cpu_id] = Some(Stage2 {
                    entry_point,
                    entry_barrier,
                    stack_addr: rsp.as_u64(),
                });
            });
    }
}
