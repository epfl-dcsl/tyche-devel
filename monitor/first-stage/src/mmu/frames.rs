use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering};

use bootloader::boot_info::{MemoryRegion, MemoryRegionKind};
use mmu::frame_allocator::PhysRange;
use mmu::memory_coloring::{
    ActiveMemoryColoring, ColorRange, MemoryColoring, MemoryColoringType, MemoryRange,
    RamRegionsInRange,
};
use mmu::ptmapper::PtMapper;
use mmu::{FrameAllocator, RangeAllocator};
use spin::Mutex;
use vmx::GuestPhysAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::PhysAddr;

use crate::guests::boot_params::{E820Entry, E820Types};
use crate::second_stage::SECOND_STAGE_SIZE;
use crate::{allocator, println, vmx, HostPhysAddr, HostVirtAddr};

pub const PAGE_SIZE: usize = 0x1000;

/// How much memory to reserve for the second stage
/// Gibibyte as bytes
const GIB: usize = 1 << 30;
const MIB: usize = 1 << 20;
const GUEST_RESERVED_MEMORY: usize = 4 * GIB;
const SECOND_STAGE_RESERVED_MEMORY: u64 = 400 * MIB as u64;

// ————————————————————————— Physical Memory Offset ————————————————————————— //

static PHYSICAL_MEMORY_OFFSET: AtomicUsize = AtomicUsize::new(PHYSICAL_OFFSET_GUARD);

const PHYSICAL_OFFSET_GUARD: usize = usize::MAX;

/// Set the global physical memory offset.
///
/// The offset corresponds to the offset of the virtual memory with respect to the physical memory.
/// It is fixed by the bootloader and never updated afterward.
fn set_physical_memory_offset(offset: HostVirtAddr) {
    PHYSICAL_MEMORY_OFFSET
        .compare_exchange(
            PHYSICAL_OFFSET_GUARD,
            offset.as_usize(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .expect("Physical memory offset was initialized more than onece.");
}

/// Retrieves the global memory offset betwen virtual and physical memory.
///
/// This function should only be called after memory subsytem initialization.
pub fn get_physical_memory_offset() -> HostVirtAddr {
    let offset = PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst);

    // Check that the offset was properly initialized
    if offset == PHYSICAL_OFFSET_GUARD {
        panic!("Tried to read global physical memory offset prior to initialization");
    }

    HostVirtAddr::new(offset)
}

// ————————————————————————— Memory Initialization —————————————————————————— //

/// How the memory is split between host and guest.
pub struct MemoryMap {
    pub guest: &'static [MemoryRegion],
    pub host: PhysRange,
}

/// Describes what a certain memory area is reserved/used for
pub enum MemoryPartition {
    STAGE1,
    STAGE2,
    GUEST,
    UNUSED,
}

/// Describes the memory layout created in stage1
pub struct PartitionedMemoryMap<T: MemoryColoring + Clone> {
    /// Memory reserved for root partition/Dom0
    pub guest: MemoryRange,
    /// Memory used for Stage 1
    pub stage1: MemoryRange,
    /// Memory used for Stage 2
    pub stage2: MemoryRange,
    /// Memory that is not allocated to any partition yet. Intended for TDs
    pub unused: MemoryRange,
    /// Memory coloring function
    coloring: Option<T>,
    ///memory map from early bootloader
    all_regions: &'static [MemoryRegion],
}

impl<T: MemoryColoring + Clone> PartitionedMemoryMap<T> {
    pub fn print_layout(&self) {
        log::info!("guest memory range  : {:x?}", self.guest);
        log::info!("stage1 memory range : {:x?}", self.stage1);
        log::info!("stage2 memory range : {:x?}", self.stage2);
        log::info!("unused memory       : {:x?}", self.unused);
    }

    pub fn print_mem_regions(&self) {
        for (mr_idx, mr) in self.all_regions.iter().enumerate() {
            println!("idx {:02} {:x?}", mr_idx, mr);
        }
    }

    pub fn get_boot_memory_regions(&self) -> &[MemoryRegion] {
        &self.all_regions
    }

    pub fn new(
        guest: MemoryRange,
        stage1: MemoryRange,
        stage2: MemoryRange,
        unused: MemoryRange,
        all_regions: &'static [MemoryRegion],
        coloring: Option<T>,
    ) -> Self {
        Self {
            guest,
            stage1,
            stage2,
            unused,
            coloring,
            all_regions,
        }
    }

    /// Build memory regions for the GPA space that we will construct for the guest in stage2
    /// We need to construct them here, because we have to load them into memory and we want to avoid
    /// doing that from stage2
    pub fn build_guest_memory_regions(&self) -> Vec<E820Entry> {
        /* 1) Keep Memory holes where they are (gaps between entry)
           2) Keep everything that is marked as reserved where it is (UnknownUefi(_) and UnknownBios(_))
           3) Out of caution, also Keep "Bootloader" where it is
           4) For remaining usable Regions: Mark as reserved at free will to fit the actually
           available memory
        */
        let mut result = Vec::new();

        let guest_mem_bytes = match self.guest {
            MemoryRange::ColoredRange(cr) => cr.mem_bytes,
            MemoryRange::AllRamRegionInRange(rr) => rr.mem_bytes,
            MemoryRange::SinglePhysContigRange(_) => {
                panic!("SinglePhysContigRange range is not supported for describing guest memory")
            }
        };
        let mut remaining_guest_mem_bytes = guest_mem_bytes as u64;

        let mut ram_bytes = 0;
        let mut device_bytes = 0;
        let mut bootloader_ram_bytes = 0;

        for bl_mr in self.all_regions {
            let bl_mr_bytes = bl_mr.end - bl_mr.start;
            assert_eq!(remaining_guest_mem_bytes % PAGE_SIZE as u64, 0);
            match bl_mr.kind {
                MemoryRegionKind::Usable => {
                    //No more guest memory,
                    if remaining_guest_mem_bytes <= 0 {
                        result.push(E820Entry {
                            addr: GuestPhysAddr::new(bl_mr.start as usize),
                            size: bl_mr_bytes,
                            mem_type: E820Types::Reserved,
                        });
                    //remaining guest memory is >=  bl_mr -> use whole region
                    } else if remaining_guest_mem_bytes >= bl_mr_bytes {
                        result.push(E820Entry {
                            addr: GuestPhysAddr::new(bl_mr.start as usize),
                            size: bl_mr_bytes,
                            mem_type: E820Types::Ram,
                        });
                        remaining_guest_mem_bytes -= bl_mr_bytes;
                        ram_bytes += bl_mr_bytes;
                    // remaining guest memory > 0 but smaller than region -> split region
                    } else {
                        result.push(E820Entry {
                            addr: GuestPhysAddr::new(bl_mr.start as usize),
                            size: remaining_guest_mem_bytes,
                            mem_type: E820Types::Ram,
                        });
                        result.push(E820Entry {
                            addr: GuestPhysAddr::new(
                                (bl_mr.start + remaining_guest_mem_bytes) as usize,
                            ),
                            size: bl_mr_bytes - remaining_guest_mem_bytes,
                            mem_type: E820Types::Reserved,
                        });
                        ram_bytes += remaining_guest_mem_bytes;
                        assert!(
                            remaining_guest_mem_bytes > 0
                                && remaining_guest_mem_bytes < bl_mr_bytes
                        );
                        remaining_guest_mem_bytes = 0;
                    }
                }
                //TODO: This enables some color interference, but we need it for linux to boot
                // Copy information to memory with dom0 color and hide this in the EPTs?
                MemoryRegionKind::Bootloader => {
                    result.push(E820Entry {
                        addr: GuestPhysAddr::new(bl_mr.start as usize),
                        size: bl_mr_bytes,
                        mem_type: E820Types::Ram,
                    });
                    device_bytes += bl_mr_bytes;
                    bootloader_ram_bytes += bl_mr_bytes;
                }
                //passthrough
                MemoryRegionKind::UnknownUefi(_) | MemoryRegionKind::UnknownBios(_) => {
                    result.push(E820Entry {
                        addr: GuestPhysAddr::new(bl_mr.start as usize),
                        size: bl_mr_bytes,
                        mem_type: E820Types::Reserved,
                    });
                    device_bytes += bl_mr_bytes;
                }
                _ => todo!("Unknown boot loader memory type when building guest memory regions"),
            }
        }

        //tell linux about stage1 allocator memory. we use this e.g. for some ACPI data
        //It probably is enough to make sure that stage2 maps this into the EPTs but it
        //felt bettter to also include this into the boot memory map
        let stage1_alloc_mem = match self.stage1 {
            MemoryRange::ColoredRange(_) => panic!("should not happend"),
            MemoryRange::SinglePhysContigRange(pcr) => pcr,
            MemoryRange::AllRamRegionInRange(_) => panic!("should not happen"),
        };
        result.push(E820Entry {
            addr: GuestPhysAddr::new(stage1_alloc_mem.start.as_usize()),
            size: stage1_alloc_mem.size() as u64,
            mem_type: E820Types::Reserved,
        });

        log::info!(
            "RAM: {:0.2} GiB (0x{:x} bytes). Device {:0.2} GiB (0x{:x} bytes)",
            ram_bytes as f64 / (1 << 30) as f64,
            ram_bytes,
            device_bytes as f64 / (1 << 30) as f64,
            device_bytes
        );

        result
    }

    ///Create phys ranges for all useable RAM memory in the specified range.
    /// "Useable" is defined by the passed memory region description
    pub fn iterate_over_ranges_for_mem_range<F: FnMut(PhysRange)>(
        regions: &[MemoryRegion],
        range: PhysRange,
        mut range_cb: F,
    ) {
        for mr in regions {
            //mr is before the allowed range
            if mr.end < range.start.as_u64() {
                continue;
            }
            //mr ist after allowed range, since sorted thered cannot be any more matching memory ranges
            if range.end.as_u64() < mr.start {
                break;
            }
            //mr overlaps with allowed range
            if range.start.as_u64() >= mr.start {
                //mr is completely contained
                if range.end.as_u64() >= mr.end {
                    range_cb(PhysRange {
                        start: HostPhysAddr::new(mr.start as usize),
                        end: HostPhysAddr::new(mr.end as usize),
                    });
                } else {
                    //allowed range ends in mr
                    range_cb(PhysRange {
                        start: HostPhysAddr::new(mr.start as usize),
                        end: range.end,
                    });
                }
            }
        }
    }

    /// Calls range_cb for each physical contiguous memory range that belongs to `partition`
    pub fn iterate_over_ranges_for_mem_partition<F: FnMut(PhysRange)>(
        &self,
        partition: MemoryPartition,
        mut range_cb: F,
    ) {
        let memory_range = match partition {
            MemoryPartition::STAGE1 => &self.stage1,
            MemoryPartition::STAGE2 => &self.stage2,
            MemoryPartition::GUEST => &self.guest,
            MemoryPartition::UNUSED => &self.unused,
        };

        match &memory_range {
            MemoryRange::ColoredRange(cr) => self.vist_all_ranges_for_color(cr, range_cb),
            MemoryRange::SinglePhysContigRange(pr) => range_cb(*pr),
            MemoryRange::AllRamRegionInRange(rr) => {
                Self::iterate_over_ranges_for_mem_range(&self.all_regions, rr.range, range_cb)
            }
        }
    }

    /// Iterates over all physical memory that belongs to the specified color_range.
    /// For each contiguous physical memory range the call back function is called
    fn vist_all_ranges_for_color<F: FnMut(PhysRange)>(
        &self,
        color_range: &ColorRange,
        range_cb: F,
    ) {
        /* hacky use of allocator. This allocator does not "do anyhting" to the pages,
         * but simply iterates over them, adhering to the coloring and alignment requirements.
         * Here, we just use it to get the count of all frames with this color;
         * The value of the `physical_memory_offset` argument is not important here
         */
        let coloring = self.coloring.as_ref().expect("PartitionedMemoryMap misconfiguration. Do not have coloring but vist_all_ranges_for_color was requested");
        let allocator = ColoringRangeFrameAllocator::new(
            color_range.first_color,
            color_range.color_count,
            HostVirtAddr::new(0),
            self.all_regions,
            coloring,
            None,
        );
        allocator
            .allocate_range(color_range.mem_bytes, range_cb)
            .expect("MemoryColoring::compute_ranges_for_color : alloc range failed");
    }
}

/// Create allocator for guest based on `color-dom0` compile time switch
/// Returns (guest allocator, guest memory range, unused memory range)
/// # Arguments
/// - `next_free_color` : This is the first color that may be used by any coloring allocator in this range.
/// In case of not coloring dom0 this should be 0
pub fn create_guest_allocator<T: MemoryColoring + Clone>(
    regions: &'static [MemoryRegion],
    mem_painter: T,
    next_free_color: u64,
    physical_memory_offset: HostVirtAddr,
) -> (ColoringRangeFrameAllocator<T>, MemoryRange, MemoryRange) {
    #[cfg(feature = "color-dom0")]
    {
        log::info!("Computing number of colors required for dom0");
        let (first_guest_color, guest_color_count, guest_mem_bytes) = contig_color_range(
            regions,
            &mem_painter.clone(),
            next_free_color,
            MemoryColoringType::COLOR_COUNT as u64,
            GUEST_RESERVED_MEMORY,
        )
        .expect("failed to gather colors for guest memory");
        let guest_allocator = ColoringRangeFrameAllocator::new(
            first_guest_color,
            guest_color_count,
            physical_memory_offset,
            regions,
            &mem_painter,
            None,
        );
        let guest_mem_partition = MemoryRange::ColoredRange(ColorRange {
            first_color: first_guest_color,
            color_count: guest_color_count,
            mem_bytes: guest_mem_bytes,
        });
        let first_unused_color = first_guest_color + guest_color_count;
        let mut unused_mem_bytes = 0;
        for color_id in (first_unused_color as usize)..MemoryColoringType::COLOR_COUNT {
            unused_mem_bytes +=
                compute_color_partition_size(regions, &mem_painter, color_id as u64);
        }
        let unused_memory_partition = MemoryRange::ColoredRange(ColorRange {
            first_color: first_unused_color,
            color_count: MemoryColoringType::COLOR_COUNT as u64 - first_unused_color,
            mem_bytes: unused_mem_bytes,
        });
        return (
            guest_allocator,
            guest_mem_partition,
            unused_memory_partition,
        );
    }
    #[cfg(not(feature = "color-dom0"))]
    {
        //create coloring allocator with access to all colors. This is
        //basically equal to the boot frame allocator that was previously used
        assert_eq!(
            next_free_color, 0,
            "Using uncolored dom0 assumes that whole color range is available"
        );

        //compute lowest and highest HPA that we will use to fullill allocations
        //this info is only valid in combination with the memory map, similar to coloring
        let mut guest_start_hpa = None;
        let mut guest_end_hpa = 0;
        let mut remaining_bytes = GUEST_RESERVED_MEMORY as u64;
        for mr in regions {
            if mr.kind != MemoryRegionKind::Usable {
                continue;
            }
            if guest_start_hpa.is_none() {
                guest_start_hpa = Some(mr.start);
            }
            let mr_size = mr.end - mr.start;
            //memory region is larger than remaining requires bytes
            if mr_size > remaining_bytes {
                assert_eq!(remaining_bytes as usize % PAGE_SIZE, 0);
                let early_end = mr.start + remaining_bytes;
                guest_end_hpa = early_end;
                remaining_bytes = 0;
                break;
            }

            //can use whole memory region
            remaining_bytes -= mr_size;
            guest_end_hpa = mr.end;
        }
        assert_eq!(remaining_bytes, 0, "Not enough memory to fullfill request");
        let guest_start_hpa = guest_start_hpa.expect("did not find any useable memory range");

        //allow all colors but add range filter
        let guest_allocator = ColoringRangeFrameAllocator::new(
            0,
            ActiveMemoryColoring::COLOR_COUNT as u64,
            physical_memory_offset,
            regions,
            &mem_painter,
            Some((guest_start_hpa as usize, guest_end_hpa as usize)),
        );

        let guest_mem_partition = MemoryRange::AllRamRegionInRange(RamRegionsInRange {
            range: PhysRange {
                start: HostPhysAddr::new(guest_start_hpa as usize),
                end: HostPhysAddr::new(guest_end_hpa as usize),
            },
            mem_bytes: GUEST_RESERVED_MEMORY,
        });
        let last_ram_region = regions
            .iter()
            .rev()
            .find(|v| v.kind == MemoryRegionKind::Usable)
            .unwrap();
        let unused_memory_range = PhysRange {
            start: HostPhysAddr::new(guest_start_hpa as usize),
            end: HostPhysAddr::new(last_ram_region.end as usize),
        };
        let mut unused_memory_range_size = 0;
        PartitionedMemoryMap::<T>::iterate_over_ranges_for_mem_range(
            &regions,
            unused_memory_range,
            |pr| unused_memory_range_size += pr.size(),
        );
        let unused_mem_partition = MemoryRange::AllRamRegionInRange(RamRegionsInRange {
            range: unused_memory_range,
            mem_bytes: unused_memory_range_size,
        });
        return (guest_allocator, guest_mem_partition, unused_mem_partition);
    }
}

/// Uses conditional compilation create either a coloring or a regular
/// allocator for stage2
pub unsafe fn create_stage2_allocator<T: MemoryColoring + Clone>(
    physical_memory_offset: HostVirtAddr,
    _regions: &'static [MemoryRegion],
    _mem_painter: &T,
    stage2_contig_mr: Option<PhysRange>,
) -> (impl RangeAllocator, u64, MemoryRange) {
    #[cfg(feature = "color-s2")]
    {
        let (first_stage2_color, stage2_color_count, stage2_mem_bytes) = contig_color_range(
            _regions,
            _mem_painter,
            0,
            MemoryColoringType::COLOR_COUNT as u64,
            SECOND_STAGE_SIZE,
        )
        .expect("failed to gather colors for stage2 allocator");
        let stage2_allocator = ColoringRangeFrameAllocator::new(
            first_stage2_color,
            stage2_color_count,
            physical_memory_offset,
            _regions,
            _mem_painter,
        );
        let next_free_color = first_stage2_color + stage2_color_count;
        let stage2_mem_partiton = MemoryRange::ColoredRange(ColorRange {
            first_color: first_stage2_color,
            color_count: stage2_color_count,
            mem_bytes: stage2_mem_bytes,
        });
        return (stage2_allocator, next_free_color, stage2_mem_partiton);
    }

    #[cfg(not(feature = "color-s2"))]
    {
        let stage2_contig_mr = stage2_contig_mr.expect("create_stage2_allocator called for uncolored stage 2 but no stage2_contig_mr was provided");
        println!(
            "Creating contiguous, uncolored allocator for s2. Using Range {:x?}",
            stage2_contig_mr
        );
        let stage2_allocator = RangeFrameAllocator::new(
            stage2_contig_mr.start,
            stage2_contig_mr.end,
            physical_memory_offset,
        );
        let next_free_color = 0;
        let stage2_mem_partiton = MemoryRange::SinglePhysContigRange(stage2_contig_mr);
        return (stage2_allocator, next_free_color, stage2_mem_partiton);
    }
}

/// Initializes the memory subsystem.
///
/// After success, the memory subsystem is operationnal, meaning that the global allocator is
/// availables (and thus heap allocated values such as `Box` and `Vec` can be used).
///
/// Return values:
///  - Host frame allocator
///  - Guest frame allocator
///  - color map
///  - The host memory mapper
///
/// SAFETY: This function must be called **at most once**, and the boot info must contain a valid
/// mapping of the physical memory.
pub unsafe fn init(
    physical_memory_offset: HostVirtAddr,
    regions: &'static mut [MemoryRegion],
) -> Result<
    (
        impl RangeAllocator,
        impl RangeAllocator,
        impl RangeAllocator,
        PartitionedMemoryMap<MemoryColoringType>,
        PtMapper<HostPhysAddr, HostVirtAddr>,
    ),
    (),
> {
    //just out of caution that using these low regions might lead to trouble
    /*for mr in regions.iter_mut() {
        if mr.start < 0xa0000 && mr.kind == MemoryRegionKind::Usable {
            mr.kind = MemoryRegionKind::UnknownBios(1);
        }
    }*/
    let stage2_phys_range = if cfg!(feature = "color-s2") {
        println!("\nUsing colors for stage2\n");
        None
    } else {
        println!("\nNot using colors for stage2\n");
        Some(
            reserve_memory_region(regions, SECOND_STAGE_RESERVED_MEMORY as usize)
                .expect("failed to reserve memory for stage2"),
        )
    };

    // Initialize physical memory offset
    set_physical_memory_offset(physical_memory_offset);

    /* Locate memory region that has enough memory for the stage1 allocations.
     * We don't need to consider colors here, as stage1 in only used during early boot.
     * We expect that most systems will only have very coarse grained coloring.
     * Thus, it would be bad to "waste" a color here
     */
    let required_bytes_stage1_alloc = SECOND_STAGE_RESERVED_MEMORY as usize - SECOND_STAGE_SIZE;
    let contig_mr_for_stage1_alloc = reserve_memory_region(regions, required_bytes_stage1_alloc)
        .expect("failed to reserve memory for stage1");
    let stage1_allocator = RangeFrameAllocator::new(
        contig_mr_for_stage1_alloc.start,
        contig_mr_for_stage1_alloc.end,
        physical_memory_offset,
    );
    let stage1_mem_partition = MemoryRange::SinglePhysContigRange(contig_mr_for_stage1_alloc);

    let mem_painter = MemoryColoringType {};

    let (stage2_allocator, next_free_color, stage2_mem_partiton) = create_stage2_allocator(
        physical_memory_offset,
        regions,
        &mem_painter,
        stage2_phys_range,
    );

    let (guest_allocator, guest_mem_partition, unused_mem_partiton) = create_guest_allocator(
        regions,
        mem_painter.clone(),
        next_free_color,
        physical_memory_offset,
    );

    let memory_partitions = PartitionedMemoryMap::new(
        guest_mem_partition,
        stage1_mem_partition,
        stage2_mem_partiton,
        unused_mem_partiton,
        regions,
        Some(mem_painter),
    );

    // Initialize the frame allocator and the memory mapper.
    let (level_4_table_frame, _) = Cr3::read();
    let pt_root = HostPhysAddr::new(level_4_table_frame.start_address().as_u64() as usize);
    println!("About to create pt_mapper");
    let mut pt_mapper = PtMapper::new(physical_memory_offset.as_usize(), 0, pt_root);
    println!("created pt_mapper\nAbout to init heap");

    // Initialize the heap.
    allocator::init_heap(&mut pt_mapper, &stage1_allocator)?;
    println!("Initialized heap\nAbout to transofmr guest_allocator into shared allocator\n");
    let guest_allocator = SharedFrameAllocator::new(guest_allocator);
    println!("init memory done");

    Ok((
        stage1_allocator,
        stage2_allocator,
        guest_allocator,
        memory_partitions,
        pt_mapper,
    ))
}

/// Searches and returns a memory region a physically contiguous memory range
/// of the requested size. `regions` is modified to make the memory unavailable to other parts of the system
fn reserve_memory_region(regions: &mut [MemoryRegion], required_bytes: usize) -> Option<PhysRange> {
    let mut matching_mr = None;
    for (mr_idx, mr) in regions.iter().enumerate().rev() {
        if mr.kind == MemoryRegionKind::Usable && ((mr.end - mr.start) as usize > required_bytes) {
            let pr = PhysRange {
                start: HostPhysAddr::new(mr.start as usize),
                end: HostPhysAddr::new(mr.end as usize),
            };

            matching_mr = Some((mr_idx, pr));
            break;
        }
    }
    match &mut matching_mr {
        Some((idx, pr)) => {
            //if this is the last region, just could it short instead of marking as reserved
            //this way another call to reserve_memory_region can easily draw from the same region again
            if *idx == regions.len() - 1 {
                let v = &mut regions[*idx];

                pr.start = HostPhysAddr::new(v.end as usize - required_bytes);
                pr.end = HostPhysAddr::new(v.end as usize);
                assert_eq!(pr.start.as_usize() % PAGE_SIZE, 0);
                assert_eq!(pr.end.as_usize() % PAGE_SIZE, 0);

                v.end -= required_bytes as u64;
            } else {
                panic!("should not happend");
            }

            return Some(*pr);
        }
        None => return None,
    }
}

// ———————————————————————————— Coloring Range Frame Allocator ————————————————//

#[derive(Debug, Clone, Copy)]
struct CurrentRegion {
    idx: usize,
    aligned_end: u64,
}

pub struct ColoringRangeFrameAllocator<T: MemoryColoring> {
    memory_regions: &'static [MemoryRegion],
    cur_region: Cell<CurrentRegion>,
    inside_cur_region_cursor: Cell<PhysAddr>,
    physical_memory_offset: HostVirtAddr,
    memory_coloring: T,
    //id of the first color that this allocator is allowed to use
    first_color: u64,
    //number of contiguous colors, starting at `first_color`, that this allocator may use
    color_count: u64,
    gpa_of_next_allocation: Cell<usize>,
    //if set, only consider phys addrs in this range
    additional_range_filter: Option<(usize, usize)>,
}

impl<T: MemoryColoring + Clone> ColoringRangeFrameAllocator<T> {
    pub fn new(
        first_color: u64,
        color_count: u64,
        physical_memory_offset: HostVirtAddr,
        memory_regions: &'static [MemoryRegion],
        memory_coloring: &T,
        //if set, only consider phys addrs in this range
        additional_range_filter: Option<(usize, usize)>,
    ) -> Self {
        let cur_region_idx = 0;
        let cur_mr = &memory_regions[cur_region_idx];
        let cur_phys_start = HostPhysAddr::new(cur_mr.start as usize);
        let cur_phys_end = HostPhysAddr::new(cur_mr.end as usize);
        let cur_range_start = cur_phys_start.align_up(PAGE_SIZE).as_u64();
        let cur_range_end = cur_phys_end.align_down(PAGE_SIZE).as_u64();

        let res = Self {
            memory_regions,
            cur_region: Cell::new(CurrentRegion {
                idx: cur_region_idx,
                aligned_end: cur_range_end,
            }),
            inside_cur_region_cursor: Cell::new(PhysAddr::new(cur_range_start)),
            physical_memory_offset,
            memory_coloring: memory_coloring.clone(),
            first_color,
            color_count,
            gpa_of_next_allocation: Cell::new(0),
            additional_range_filter,
        };

        if cur_mr.kind != MemoryRegionKind::Usable {
            res.inside_cur_region_cursor.set(PhysAddr::new(cur_mr.end));
            res.gpa_of_next_allocation.set(cur_mr.end as usize);
            res.advance_to_next_region().unwrap();
        }

        res
    }

    //advance internal state to next useable region, returns error if we ran out of regions
    //this will also update the next_gpa if we skip over regions that will later be pass through mapped to the dom0
    fn advance_to_next_region(&self) -> Result<(), ()> {
        let mut prev_region = self.memory_regions[self.cur_region.get().idx];
        assert_eq!(
            self.inside_cur_region_cursor.get().as_u64(),
            prev_region.end
        );
        for (mr_idx, mr) in self
            .memory_regions
            .iter()
            .enumerate()
            .skip(self.cur_region.get().idx + 1)
        {
            //GAP -> later we add a device region here
            if prev_region.end < mr.start {
                let gap_size = (mr.start - prev_region.end) as usize;
                assert_eq!(
                    gap_size % PAGE_SIZE,
                    0,
                    "gap between regions is not multiple of page size"
                );
                let updated = self.gpa_of_next_allocation.get() + gap_size;
                self.gpa_of_next_allocation.set(updated);
            } else if prev_region.end > mr.start {
                panic!("weird unsorted memory region in gpa calculation");
            }
            //fallthrough is intended, we can have a GAP and then then e.g. the region is also not useable
            match mr.kind {
                MemoryRegionKind::Usable => {
                    //update reference to current region
                    self.cur_region.set(CurrentRegion {
                        idx: mr_idx,
                        aligned_end: HostPhysAddr::new(mr.end as usize)
                            .align_down(PAGE_SIZE)
                            .as_u64(),
                    });
                    //update reference to position inside the region to start of the new region
                    let region_start = HostPhysAddr::new(mr.start as usize)
                        .align_up(PAGE_SIZE)
                        .as_u64();
                    self.inside_cur_region_cursor
                        .set(PhysAddr::new(region_start));
                    return Ok(());
                }
                MemoryRegionKind::Bootloader
                | MemoryRegionKind::UnknownUefi(_)
                | MemoryRegionKind::UnknownBios(_) => {
                    let size = (mr.end - mr.start) as usize;
                    assert_eq!(
                        size % PAGE_SIZE,
                        0,
                        "blocked region has size that is not multiple of page size"
                    );
                    let updated: usize = self.gpa_of_next_allocation.get() + size;
                    self.gpa_of_next_allocation.set(updated);
                }
                _ => todo!("unknown memory region"),
            }

            prev_region = *mr;
        }
        return Err(());
    }

    //get next frame inside the currently selected region or return None if we hit the end
    //DOES NOT check for color, use `next_frame_in_region_with_color` to ensure that returned frame has allowed color
    fn next_frame_in_region(&self) -> Option<vmx::Frame> {
        let cursor = self.inside_cur_region_cursor.get();
        if cursor.as_u64() < self.cur_region.get().aligned_end {
            self.inside_cur_region_cursor.set(cursor + PAGE_SIZE as u64);
            Some(vmx::Frame {
                phys_addr: vmx::HostPhysAddr::new(cursor.as_u64() as usize),
                virt_addr: (cursor.as_u64() as usize
                    + self.physical_memory_offset.as_u64() as usize),
            })
        } else {
            None
        }
    }

    //returns the next frame in the current region that has an allowed color or None if the end of the region is reached
    fn next_frame_in_region_with_color(&self) -> Option<vmx::Frame> {
        let mut next_frame = match self.next_frame_in_region() {
            Some(v) => v,
            None => return None,
        };
        let correct_color = |addr: HostPhysAddr| {
            let frame_color = self.memory_coloring.compute_color(addr);
            return (frame_color >= self.first_color)
                && (frame_color < (self.first_color + self.color_count));
        };
        while !correct_color(next_frame.phys_addr) {
            next_frame = match self.next_frame_in_region() {
                Some(v) => v,
                None => return None,
            };
        }
        if correct_color(next_frame.phys_addr) {
            return Some(next_frame);
        } else {
            return None;
        }
    }
}

unsafe impl<T: MemoryColoring + Clone> FrameAllocator for ColoringRangeFrameAllocator<T> {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let mut next_frame = self.next_frame_in_region_with_color();

        let is_frame_in_allowed_range = |frame: vmx::Frame| match self.additional_range_filter {
            Some((allowed_start, allowed_end)) => {
                allowed_start <= frame.phys_addr.as_usize()
                    && frame.phys_addr.as_usize() < allowed_end
            }
            None => true,
        };
        //if None, advance region and try again until we run out of regions
        while next_frame.is_none()
            || next_frame.is_some_and(|frame| !is_frame_in_allowed_range(frame))
        {
            //if next frame is larger than allowed_end there will be no more valid frames -> we ran out of memory
            //This improves performance as we do not iterate untill the end of all memory ranges
            match (next_frame, self.additional_range_filter) {
                (Some(next_frame), Some((_, allowed_end))) => {
                    if next_frame.phys_addr.as_usize() >= allowed_end {
                        return None;
                    }
                }
                _ => (),
            }
            if next_frame.is_none() && self.advance_to_next_region().is_err() {
                return None;
            }
            next_frame = self.next_frame_in_region_with_color();
        }
        if next_frame.is_some() {
            let tmp = self.gpa_of_next_allocation.get();
            self.gpa_of_next_allocation.set(tmp + PAGE_SIZE);
        }
        return next_frame;
    }

    fn get_boundaries(&self) -> (usize, usize) {
        log::error!("get_boundaries called");
        panic!("TODO: remove this function from trait. It is not used and does not align with the painted memory world view");
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        self.physical_memory_offset
    }
}

unsafe impl<T: MemoryColoring + Clone> RangeAllocator for ColoringRangeFrameAllocator<T> {
    fn gpa_of_next_allocation(&self) -> vmx::GuestPhysAddr {
        let cur_region = self.cur_region.get();
        if self.inside_cur_region_cursor.get().as_u64() == cur_region.aligned_end {
            if self.advance_to_next_region().is_err() {
                panic!("allcator is OOM");
            }
        }
        GuestPhysAddr::new(self.gpa_of_next_allocation.get())
    }
    fn allocate_range<F: FnMut(PhysRange)>(&self, size: usize, mut store_cb: F) -> Result<(), ()> {
        //edge case: at most one page requested
        if size <= PAGE_SIZE {
            let frame = match self.allocate_frame() {
                Some(v) => v,
                None => return Err(()),
            };
            store_cb(PhysRange {
                start: frame.phys_addr,
                end: frame.phys_addr + PAGE_SIZE,
            });
            return Ok(());
        }

        //normal case: need at least two pages for request
        let first_phy_addr = match self.allocate_frame() {
            Some(v) => v.phys_addr,
            None => return Err(()),
        };
        let mut cur_range = PhysRange {
            start: first_phy_addr,
            end: first_phy_addr + PAGE_SIZE,
        };
        /*N.B. we use signed type here as allocations might not be multiple of PAGE_SIZE
        but since we only alloc with PAGE_SIZE granularity, remaining_bytes might become negative in
        the final iteration
        */
        let mut remaining_bytes: i64 = (size - PAGE_SIZE) as i64;
        //normal case: multiple pages, allocate frames, and group them together if they are contiguous
        while remaining_bytes > 0 {
            let next = match self.allocate_frame() {
                Some(v) => v.phys_addr,
                None => return Err(()),
            };
            if next == cur_range.end {
                //Case 1: contiguous -> extend cur_range
                cur_range.end = cur_range.end + PAGE_SIZE;
            } else {
                //Case 2: not contiguous, start new range
                //ranges.push(cur_range);
                store_cb(cur_range);
                cur_range = PhysRange {
                    start: next,
                    end: next + PAGE_SIZE,
                };
            }
            remaining_bytes -= PAGE_SIZE as i64;
        }
        //store final range before returning
        store_cb(cur_range);
        Ok(())
    }
}

/// Compute contiguous color range required for `required_bytes` bytes
/// # Arguments
/// - `total_color_count` absolute number of colors provided by the coloring
/// # Returns
/// On succcess returns tuple (first color id, color count, size in bytes)
fn contig_color_range<T: MemoryColoring + Clone>(
    all_regions: &'static [MemoryRegion],
    coloring: &T,
    first_usable_color_id: u64,
    total_color_count: u64,
    required_bytes: usize,
) -> Result<(u64, u64, usize), ()> {
    let first_used_color = first_usable_color_id;
    let mut color_count = 1;
    let mut mem_bytes = compute_color_partition_size(all_regions, coloring, first_used_color);
    for new_color in first_usable_color_id + 1..total_color_count {
        if mem_bytes > required_bytes {
            break;
        }
        let new_color_bytes =
            compute_color_partition_size(all_regions.as_ref(), coloring, new_color as u64);
        mem_bytes += new_color_bytes;
        color_count += 1;
    }
    if mem_bytes < required_bytes {
        log::error!(
            "Depleted all {} colors but only got {} GiB ! Need {} GiB",
            total_color_count,
            mem_bytes / (1 << 30),
            required_bytes / (1 << 30)
        );

        return Err(());
    }
    return Ok((first_used_color, color_count, mem_bytes));
}

/// Computes the size of the memory partition with the given color_id in bytes
fn compute_color_partition_size<T: MemoryColoring + Clone>(
    all_regions: &'static [MemoryRegion],
    coloring: &T,
    color_id: u64,
) -> usize {
    let mut frame_count = 0;
    /* hacky use of allocator. This allocator does not "do anyhting" to the pages,
     * but simply iterates over them, adhering to the coloring and alignment requirements.
     * Here, we just use it to get the count of all frames with this color;
     * The value of the `physical_memory_offset` argument is not important here
     */
    let allocator = ColoringRangeFrameAllocator::new(
        color_id,
        1,
        HostVirtAddr::new(0),
        all_regions,
        coloring,
        None,
    );
    let mut frame_opt = allocator.allocate_frame();
    while let Some(_frame) = frame_opt {
        frame_count += 1;
        frame_opt = allocator.allocate_frame();
    }
    return frame_count * PAGE_SIZE;
}

// ———————————————————————————— Frame Allocator ————————————————————————————— //

/// A FrameAllocator that returns usable frames from the bootloader's memory map.
pub struct BootInfoFrameAllocator {
    memory_map: &'static [MemoryRegion],
    region_idx: usize,
    next_frame: u64,
}

impl BootInfoFrameAllocator {
    /// Create a FrameAllocator from the passed memory map.
    ///
    /// This function is unsafe because the caller must guarantee that the passed
    /// memory map is valid. The main requirement is that all frames that are marked
    /// as `USABLE` in it are really unused.
    pub unsafe fn init(memory_map: &'static [MemoryRegion]) -> Self {
        let region_idx = 0;
        let next_frame = memory_map[region_idx].start;
        let mut allocator = BootInfoFrameAllocator {
            memory_map,
            next_frame,
            region_idx,
        };

        // If first region is not usable, we need to move to the next usable one
        if allocator.memory_map[allocator.region_idx].kind != MemoryRegionKind::Usable {
            allocator
                .goto_next_region()
                .expect("No usable memory region");
        } else {
            log::debug!(
                "Allocating from [0x{:x}, 0x{:x}]",
                memory_map[0].start,
                memory_map[0].end
            );
        }

        // Allocate one frame, so that we don't use frame zero
        allocator
            .allocate_frame()
            .expect("Initial frame allocation failed");

        allocator
    }

    /// Allocates a single frame.
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let region = self.memory_map[self.region_idx];
        if self.next_frame >= region.end {
            if self.goto_next_region().is_ok() {
                // Retry allocation
                self.allocate_frame()
            } else {
                // All the memory is exhausted
                None
            }
        } else {
            let frame = PhysFrame::containing_address(PhysAddr::new(self.next_frame as u64));
            self.next_frame += PAGE_SIZE as u64;
            Some(frame)
        }
    }

    /// Allocates a range of physical memory
    pub fn allocate_range(&mut self, size: usize) -> Option<PhysRange> {
        let size = size as u64;
        let region = self.memory_map[self.region_idx];
        if self.next_frame + size > region.end {
            if self.goto_next_region().is_ok() {
                // Retry allocation
                self.allocate_range(size as usize)
            } else {
                // All the memory is exhausted
                None
            }
        } else {
            let start = HostPhysAddr::new(self.next_frame as usize);
            let end = HostPhysAddr::new((self.next_frame + size) as usize);
            let nb_pages = bytes_to_pages(size as usize);
            self.next_frame = self.next_frame + (nb_pages * PAGE_SIZE) as u64;
            Some(PhysRange { start, end })
        }
    }

    /// Move the cursor to the next memory region
    fn goto_next_region(&mut self) -> Result<(), ()> {
        while self.region_idx + 1 < self.memory_map.len() {
            self.region_idx += 1;

            // Check if usable
            if self.memory_map[self.region_idx].kind == MemoryRegionKind::Usable {
                log::debug!(
                    "Allocating from [0x{:x}, 0x{:x}]",
                    self.memory_map[self.region_idx].start,
                    self.memory_map[self.region_idx].end
                );
                self.next_frame = self.memory_map[self.region_idx].start;
                return Ok(());
            }
        }

        // All the memory is exhausted
        self.next_frame = self.memory_map[self.region_idx].end;
        Err(())
    }

    pub fn get_boundaries(&self) -> PhysRange {
        let first_region = self.memory_map[0];
        let last_region = self.memory_map[self.memory_map.len() - 1];
        let start = HostPhysAddr::new(first_region.start as usize);
        let end = HostPhysAddr::new(last_region.end as usize);
        PhysRange { start, end }
    }
}

// ————————————————————————— Shared Frame Allocator ————————————————————————— //

#[derive(Clone)]
pub struct SharedFrameAllocator<T: MemoryColoring + Clone> {
    alloc: Arc<Mutex<ColoringRangeFrameAllocator<T>>>,
}

impl<T: MemoryColoring + Clone> SharedFrameAllocator<T> {
    pub fn new(alloc: ColoringRangeFrameAllocator<T>) -> Self {
        Self {
            alloc: Arc::new(Mutex::new(alloc)),
        }
    }
}

unsafe impl<T: MemoryColoring + Clone> FrameAllocator for SharedFrameAllocator<T> {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let inner = self.alloc.lock();
        inner.allocate_frame()
    }

    fn get_boundaries(&self) -> (usize, usize) {
        todo!("remove this");
        /*let mut inner = self.alloc.lock();
        let inner = inner.deref_mut();
        let range = inner.get_boundaries();
        (range.start.as_u64() as usize, range.end.as_u64() as usize)*/
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        self.alloc.lock().get_physical_offset()
    }
}

unsafe impl<T: MemoryColoring + Clone> RangeAllocator for SharedFrameAllocator<T> {
    fn allocate_range<F: FnMut(PhysRange)>(&self, size: usize, store_cb: F) -> Result<(), ()> {
        let inner = self.alloc.lock();
        inner.allocate_range(size, store_cb)
    }

    fn gpa_of_next_allocation(&self) -> GuestPhysAddr {
        let inner = self.alloc.lock();
        inner.gpa_of_next_allocation()
    }
}

// ————————————————————————— Range Frame Allocator —————————————————————————— //

pub struct RangeFrameAllocator {
    range_start: PhysAddr,
    range_end: PhysAddr,
    cursor: Cell<PhysAddr>,
    physical_memory_offset: HostVirtAddr,
}

impl RangeFrameAllocator {
    pub unsafe fn new(
        range_start: HostPhysAddr,
        range_end: HostPhysAddr,
        physical_memory_offset: HostVirtAddr,
    ) -> Self {
        log::debug!(
            "Allocator range: [0x{:x}, 0x{:x}]",
            range_start.as_usize(),
            range_end.as_usize()
        );
        let range_start = range_start.align_up(PAGE_SIZE).as_u64();
        let range_end = range_end.align_down(PAGE_SIZE).as_u64();
        Self {
            range_start: PhysAddr::new(range_start),
            range_end: PhysAddr::new(range_end),
            cursor: Cell::new(PhysAddr::new(range_start)),
            physical_memory_offset,
        }
    }
}

unsafe impl FrameAllocator for RangeFrameAllocator {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let cursor = self.cursor.get();
        if cursor.as_u64() < self.range_end.as_u64() {
            self.cursor.set(cursor + PAGE_SIZE as u64);
            Some(vmx::Frame {
                phys_addr: vmx::HostPhysAddr::new(cursor.as_u64() as usize),
                virt_addr: (cursor.as_u64() as usize
                    + self.physical_memory_offset.as_u64() as usize),
            })
        } else {
            log::error!(
                "RangeFramgeAllocator ran out of memory. Range [0x{:x},0x{:x}[, current pos 0x{:x}",
                self.range_start,
                self.range_end,
                self.cursor.get()
            );
            None
        }
    }

    fn get_boundaries(&self) -> (usize, usize) {
        (
            self.range_start.as_u64() as usize,
            self.range_end.as_u64() as usize,
        )
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        self.physical_memory_offset
    }
}

unsafe impl RangeAllocator for RangeFrameAllocator {
    fn gpa_of_next_allocation(&self) -> GuestPhysAddr {
        GuestPhysAddr::new((self.cursor.get() - self.range_start) as usize)
    }

    fn allocate_range<F: FnMut(PhysRange)>(&self, size: usize, mut store_cb: F) -> Result<(), ()> {
        let cursor = self.cursor.get();
        if cursor + size < self.range_end {
            let new_cursor = (cursor + size).align_up(PAGE_SIZE as u64);
            self.cursor.set(new_cursor);
            let range = PhysRange {
                start: HostPhysAddr::new(cursor.as_u64() as usize),
                end: HostPhysAddr::new(new_cursor.as_u64() as usize),
            };
            //let mut res = Vec::new();
            //res.push(range);
            store_cb(range);
            Ok(())
        } else {
            Err(())
        }
    }

    /*fn allocate_range(&self, size: usize) -> Option<StackList<PhysRange>> {
        let cursor = self.cursor.get();
        if cursor + size < self.range_end {
            let new_cursor = (cursor + size).align_up(PAGE_SIZE as u64);
            self.cursor.set(new_cursor);
            let range = PhysRange {
                start: HostPhysAddr::new(cursor.as_u64() as usize),
                end: HostPhysAddr::new(new_cursor.as_u64() as usize),
            };
            let list = StackList {
                data: range,
                prev: None,
            };
            Some(list)
        } else {
            None
        }
    }*/
}

// ———————————————————————————— Helper Functions ———————————————————————————— //

/// Returns the number of pages to add in order to grow by at least `n` bytes.
fn bytes_to_pages(n: usize) -> usize {
    let page_aligned = (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    page_aligned / PAGE_SIZE
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn bytes_to_pages() {
        assert_eq!(super::bytes_to_pages(0), 0);
        assert_eq!(super::bytes_to_pages(1), 1);
        assert_eq!(super::bytes_to_pages(PAGE_SIZE - 1), 1);
        assert_eq!(super::bytes_to_pages(PAGE_SIZE), 1);
        assert_eq!(super::bytes_to_pages(PAGE_SIZE + 1), 2);
    }
}
