use std::fmt::Write;

use capa_engine::config::NB_UPDATES;
use capa_engine::{
    permission, AccessRights, Buffer, CapaEngine, CapaError, Domain, Handle, LocalCapa, MemOps,
    NextCapaToken, RegionIterator, MEMOPS_ALL,
};

/// Snapshot testing
///
/// Checks that the given struct matches the provided snap!shot.
macro_rules! snap {
    ($snap:expr, $item:expr $(,)?) => {
        assert_eq!($snap, &format!("{}", $item));
    };
}

/// Creates a static CapaEngine and returns a mutable reference
///
/// This is required to avoid stack overflow when creating a new engine on the stack, due to the
/// size of the engine.
///
/// # SAFETY:
/// The macro returns a mutable reference to a global static, thus the usual rules applies.
/// The macro can be used multiple functions to define multiple engines in the .data section.
macro_rules! static_engine {
    () => {{
        static mut ENGINE: CapaEngine = CapaEngine::new();
        &mut ENGINE
    }};
}

// ———————————————————————————— Test our Buffer ————————————————————————————— //

#[test]
fn test_empty_buffer() {
    let mut buffer: Buffer<i32> = Buffer::new();
    assert_eq!(buffer.pop(), None);
    assert_eq!(buffer.pop(), None);
    assert_eq!(buffer.push(1), Ok(()));
    assert_eq!(buffer.pop(), Some(1));
    assert_eq!(buffer.pop(), None);
    assert_eq!(buffer.pop(), None);
}

#[test]
fn test_buffer_push_pop() {
    let mut buffer: Buffer<i32> = Buffer::new();

    // Pushing elements into the buffer
    assert_eq!(buffer.push(1), Ok(()));
    assert_eq!(buffer.push(2), Ok(()));
    assert_eq!(buffer.push(3), Ok(()));

    // Popping elements from the buffer
    assert_eq!(buffer.pop(), Some(1));
    assert_eq!(buffer.pop(), Some(2));
    assert_eq!(buffer.pop(), Some(3));
    assert_eq!(buffer.pop(), None); // Buffer should be empty now
}

#[test]
fn test_buffer_full() {
    let mut buffer: Buffer<i32> = Buffer::new();

    // Fill up the buffer
    for i in 0..NB_UPDATES {
        assert_eq!(buffer.push(i as i32), Ok(()));
    }

    // Buffer should be full now
    assert_eq!(buffer.push(100), Err(CapaError::OutOfMemory));
}

#[test]
fn test_buffer_circular_behavior() {
    let mut buffer: Buffer<i32> = Buffer::new();

    // Pushing elements into the buffer until it is full.
    for i in 0..NB_UPDATES {
        assert_eq!(buffer.push(i as i32), Ok(()));
    }

    // Popping elements from the buffer at the front
    assert_eq!(buffer.pop(), Some(0));
    assert_eq!(buffer.pop(), Some(1));

    // Pushing more elements to check circular behavior
    assert_eq!(buffer.push(NB_UPDATES as i32), Ok(()));
    assert_eq!(buffer.push(NB_UPDATES as i32 + 1), Ok(()));
    assert_eq!(buffer.push(666), Err(CapaError::OutOfMemory)); // Buffer is full, should return an error
    assert_eq!(buffer.push(777), Err(CapaError::OutOfMemory)); // Buffer is full, should return an error

    // Popping elements from the buffer
    let start: i32 = 2;
    for i in 0..NB_UPDATES {
        assert_eq!(buffer.pop(), Some(start + i as i32));
    }
    assert_eq!(buffer.pop(), None); // Buffer should be empty now
}

#[test]
fn test_buffer_contains() {
    let mut buffer: Buffer<i32> = Buffer::new();

    assert_eq!(buffer.contains(|x| { x == (0 as i32) }), false);

    // Pushing elements into the buffer until it is full.
    for i in 0..NB_UPDATES {
        assert_eq!(buffer.push(i as i32), Ok(()));
    }
    assert_eq!(buffer.contains(|x| { x == 10 }), true);

    for i in 0..10 {
        assert_eq!(buffer.pop(), Some(i as i32));
    }

    for i in 0..10 {
        assert_eq!(buffer.contains(|x| { x == (i as i32) }), false);
    }
    for i in 10..NB_UPDATES {
        assert_eq!(buffer.contains(|x| { x == (i as i32) }), true);
    }
}

// ————————————————————— EffectiveRegionIterator tests —————————————————————— //

#[test]
fn no_children_eri_direct() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    let mut iter = engine.get_effective_regions(d0, r0).unwrap();
    let region = iter.next();
    assert!(region.is_some());
    let region = region.unwrap();
    assert!(region.start == 0 && region.end == 0x1000 && region.ops == MEMOPS_ALL);
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
}

#[test]
fn start_carve_eri_direct() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    let _ = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Region([0x0, 0x500 | _URWXS])}",
        capas(d0, engine)
    );
    let mut iter = engine.get_effective_regions(d0, r0).unwrap();
    let region = iter.next();
    assert!(region.is_some());
    let region = region.unwrap();
    snap!("[0x500, 0x1000 | RWXS]", region.to_string());
    assert!(region.start == 0x500 && region.end == 0x1000 && region.ops == MEMOPS_ALL);
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
}

#[test]
fn middle_carve_eri_direct() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    let _ = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0x200,
                end: 0x300,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Region([0x200, 0x300 | _URWXS])}",
        capas(d0, engine)
    );
    let mut iter = engine.get_effective_regions(d0, r0).unwrap();
    let region = iter.next();
    assert!(region.is_some());
    let region = region.unwrap();
    snap!("[0x0, 0x200 | RWXS]", region.to_string());
    let region = iter.next().unwrap();
    snap!("[0x300, 0x1000 | RWXS]", region.to_string());
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
}

#[test]
fn end_carve_eri_direct() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    let _ = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0x500,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Region([0x500, 0x1000 | _URWXS])}",
        capas(d0, engine)
    );
    let mut iter = engine.get_effective_regions(d0, r0).unwrap();
    let region = iter.next();
    assert!(region.is_some());
    let region = region.unwrap();
    snap!("[0x0, 0x500 | RWXS]", region.to_string());
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
}

#[test]
fn chop_chop_eri_direct() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    let _ = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0x0,
                end: 0x100,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    let _ = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0x200,
                end: 0x300,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    let _ = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0x400,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    let _ = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0x900,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    let mut iter = engine.get_effective_regions(d0, r0).unwrap();
    let region = iter.next().unwrap();
    snap!("[0x100, 0x200 | RWXS]", region.to_string());
    let region = iter.next().unwrap();
    snap!("[0x300, 0x400 | RWXS]", region.to_string());
    let region = iter.next().unwrap();
    snap!("[0x500, 0x900 | RWXS]", region.to_string());
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
}

#[test]
fn no_children_eri() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();
    engine.send(d0, r0, d1_mgmt).unwrap();

    snap!("{}", regions(d0, engine));
    snap!("{[0x0, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d1, engine));
}

#[test]
fn one_carve_eri() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Do a carve.
    let _r1 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();
    engine.send(d0, r0, d1_mgmt).unwrap();

    snap!("{[0x500, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d1, engine));
    snap!("{[0x0, 0x500 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
}

// ———————————————————————————— Buffer in capas ————————————————————————————— //

#[test]
fn updates_order() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let _r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    // Check that the first update we pop is the correct one.
    snap!(
        "CreateDomain(H(0, gen 0))",
        engine.pop_update().unwrap().to_string()
    );
    snap!(
        "PermissionUpdate(H(0, gen 0))",
        engine.pop_update().unwrap().to_string()
    );
    assert_eq!(engine.pop_update().is_none(), true);
}

// ————————————————————————————— Carve regions —————————————————————————————— //
#[test]
fn simple_carve() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    snap!("{CreateDomain(H(0, gen 0))}", updates(engine));

    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    snap!("{PermissionUpdate(H(0, gen 0))}", updates(engine));
    // Carve a region.
    let r1 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    snap!("{[0x0, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Region([0x0, 0x500 | _URWXS])}",
        capas(d0, engine)
    );
    // The carve does not change the regions so it should work.
    snap!("{}", updates(engine));

    // Undo the carve and check the regions and capas.
    engine.revoke(d0, r1).unwrap();
    snap!("{[0x0, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    snap!("{Region([0x0, 0x1000 | _URWXS])}", capas(d0, engine));
}

#[test]
fn carve_lose_permissions() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    snap!("{CreateDomain(H(0, gen 0))}", updates(engine));

    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    snap!("{PermissionUpdate(H(0, gen 0))}", updates(engine));
    // Carve a region.
    let r1 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 0x500,
                ops: MemOps::READ,
            },
        )
        .unwrap();

    snap!(
        "{[0x0, 0x500 | 1 (1 - 0 - 0 - 0)] -> [0x500, 0x1000 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Region([0x0, 0x500 | _UR___])}",
        capas(d0, engine)
    );
    // The carve changes the permissions but there should be only one.
    snap!("{PermissionUpdate(H(0, gen 0))}", updates(engine));

    // Undo the carve and check the regions and capas.
    engine.revoke(d0, r1).unwrap();
    snap!("{[0x0, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    snap!("{Region([0x0, 0x1000 | _URWXS])}", capas(d0, engine));
}

#[test]
fn double_carve() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // First carve.
    let _r1 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0x0,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Try to carve the same region again.
    let invalid = engine.carve_region(
        d0,
        r0,
        AccessRights {
            start: 0x0,
            end: 0x500,
            ops: MEMOPS_ALL,
        },
    );
    assert!(invalid.is_err());
    assert_eq!(invalid.err().unwrap(), CapaError::InvalidOperation);
}

#[test]
fn carve_send() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Create a second domain.
    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();

    // Carve a region.
    let r1 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Send it to dom2.
    engine.send(d0, r1, d1_mgmt).unwrap();

    snap!("{[0x500, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    //TODO(Charly): this is not gonna be useful for the attestation.
    //It still says confidential.
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Management(2 | _)}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0x500 | 1 (1 - 1 - 1 - 1)]}", regions(d1, engine));
    snap!("{Region([0x0, 0x500 | _URWXS])}", capas(d1, engine));

    engine.revoke_domain(d1).unwrap();
    snap!("{Region([0x0, 0x1000 | _URWXS])}", capas(d0, engine));
    snap!("{[0x0, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
}

#[test]
fn carve_chop_chop() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    for i in 0..5 {
        let _ = engine
            .carve_region(
                d0,
                r0,
                AccessRights {
                    start: i,
                    end: 1 + i,
                    ops: MEMOPS_ALL,
                },
            )
            .unwrap();
    }
    snap!("{[0x0, 0x5 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    snap!("{Region([0x0, 0x5 | PURWXS]), Region([0x0, 0x1 | _URWXS]), Region([0x1, 0x2 | _URWXS]), Region([0x2, 0x3 | _URWXS]), Region([0x3, 0x4 | _URWXS]), Region([0x4, 0x5 | _URWXS])}", capas(d0, engine));
}

#[test]
fn carve_recursive_chop() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let mut carver = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    for i in 0..4 {
        carver = engine
            .carve_region(
                d0,
                carver,
                AccessRights {
                    start: 0,
                    end: (4 - i),
                    ops: MEMOPS_ALL,
                },
            )
            .unwrap();
    }
    snap!("{[0x0, 0x5 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    // TODO(Charly): that's not a lot of useful information really.
    snap!("{Region([0x0, 0x5 | PURWXS]), Region([0x0, 0x4 | PURWXS]), Region([0x0, 0x3 | PURWXS]), Region([0x0, 0x2 | PURWXS]), Region([0x0, 0x1 | _URWXS])}", capas(d0, engine));
}

#[test]
fn carve_access_rights() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Carve with less access rights.
    let r1 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 1,
                ops: MemOps::READ | MemOps::WRITE,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x1 | 1 (1 - 1 - 0 - 0)] -> [0x1, 0x5 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    snap!(
        "{Region([0x0, 0x5 | PURWXS]), Region([0x0, 0x1 | _URW__])}",
        capas(d0, engine)
    );
    // Try to cheat and get access to bigger region.
    let invalid = engine.carve_region(
        d0,
        r1,
        AccessRights {
            start: 0,
            end: 2,
            ops: MemOps::READ | MemOps::WRITE,
        },
    );
    assert!(invalid.is_err());
    assert_eq!(invalid.err().unwrap(), CapaError::InvalidOperation);

    // Now try to cheat and get more accesses from the carved region.
    let invalid = engine.carve_region(
        d0,
        r1,
        AccessRights {
            start: 0,
            end: 1,
            ops: MEMOPS_ALL,
        },
    );
    assert!(invalid.is_err());
    assert_eq!(invalid.err().unwrap(), CapaError::InvalidOperation);
}

// —————————————————————————————— Alias Region —————————————————————————————— //

#[test]
fn simple_alias() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    snap!("{CreateDomain(H(0, gen 0))}", updates(engine));

    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    snap!("{PermissionUpdate(H(0, gen 0))}", updates(engine));
    // Alias a region.
    let r1 = engine
        .alias_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    snap!(
        "{[0x0, 0x500 | 2 (2 - 2 - 2 - 2)] -> [0x500, 0x1000 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    //TODO(charly): is the first one not confusing?
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Region([0x0, 0x500 | __RWXS])}",
        capas(d0, engine)
    );
    // The alias does not change the regions so it should work.
    snap!("{}", updates(engine));

    // Undo the alias and check the regions and capas.
    engine.revoke(d0, r1).unwrap();
    snap!("{[0x0, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    snap!("{Region([0x0, 0x1000 | _URWXS])}", capas(d0, engine));
}

#[test]
fn double_alias() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // First alias.
    let _ = engine
        .alias_region(
            d0,
            r0,
            AccessRights {
                start: 0x0,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Try to alias the same region again.
    let _ = engine
        .alias_region(
            d0,
            r0,
            AccessRights {
                start: 0x0,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    snap!("{Region([0x0, 0x1000 | PURWXS]), Region([0x0, 0x500 | __RWXS]), Region([0x0, 0x500 | __RWXS])}", capas(d0, engine));
    snap!(
        "{[0x0, 0x500 | 3 (3 - 3 - 3 - 3)] -> [0x500, 0x1000 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
}

#[test]
fn alias_send() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Create a second domain.
    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();

    // Alias a region.
    let r1 = engine
        .alias_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 0x500,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Send it to dom2.
    engine.send(d0, r1, d1_mgmt).unwrap();

    snap!("{[0x0, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    //TODO(Charly): this is not gonna be useful for the attestation.
    //It still says confidential.
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Management(2 | _)}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0x500 | 1 (1 - 1 - 1 - 1)]}", regions(d1, engine));
    snap!("{Region([0x0, 0x500 | __RWXS])}", capas(d1, engine));

    engine.revoke_domain(d1).unwrap();
    snap!("{Region([0x0, 0x1000 | _URWXS])}", capas(d0, engine));
    snap!("{[0x0, 0x1000 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
}

#[test]
fn alias_chop_chop() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    for i in 0..5 {
        let _ = engine
            .alias_region(
                d0,
                r0,
                AccessRights {
                    start: i,
                    end: 1 + i,
                    ops: MEMOPS_ALL,
                },
            )
            .unwrap();
    }
    snap!("{[0x0, 0x5 | 2 (2 - 2 - 2 - 2)]}", regions(d0, engine));
    snap!("{Region([0x0, 0x5 | PURWXS]), Region([0x0, 0x1 | __RWXS]), Region([0x1, 0x2 | __RWXS]), Region([0x2, 0x3 | __RWXS]), Region([0x3, 0x4 | __RWXS]), Region([0x4, 0x5 | __RWXS])}", capas(d0, engine));
}

#[test]
fn alias_recursive_chop() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let mut carver = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    for i in 0..4 {
        carver = engine
            .alias_region(
                d0,
                carver,
                AccessRights {
                    start: 0,
                    end: (4 - i),
                    ops: MEMOPS_ALL,
                },
            )
            .unwrap();
    }
    snap!("{[0x0, 0x1 | 5 (5 - 5 - 5 - 5)] -> [0x1, 0x2 | 4 (4 - 4 - 4 - 4)] -> [0x2, 0x3 | 3 (3 - 3 - 3 - 3)] -> [0x3, 0x4 | 2 (2 - 2 - 2 - 2)] -> [0x4, 0x5 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    // TODO(Charly): that's not a lot of useful information really.
    snap!("{Region([0x0, 0x5 | PURWXS]), Region([0x0, 0x4 | P_RWXS]), Region([0x0, 0x3 | P_RWXS]), Region([0x0, 0x2 | P_RWXS]), Region([0x0, 0x1 | __RWXS])}", capas(d0, engine));
}

#[test]
fn alias_access_rights() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Alias with less access rights.
    let r1 = engine
        .alias_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 1,
                ops: MemOps::READ | MemOps::WRITE,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x1 | 2 (2 - 2 - 1 - 1)] -> [0x1, 0x5 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    snap!(
        "{Region([0x0, 0x5 | PURWXS]), Region([0x0, 0x1 | __RW__])}",
        capas(d0, engine)
    );
    // Try to cheat and get access to bigger region.
    let invalid = engine.alias_region(
        d0,
        r1,
        AccessRights {
            start: 0,
            end: 2,
            ops: MemOps::READ | MemOps::WRITE,
        },
    );
    assert!(invalid.is_err());
    assert_eq!(invalid.err().unwrap(), CapaError::InvalidOperation);

    // Now try to cheat and get more accesses from the carved region.
    let invalid = engine.alias_region(
        d0,
        r1,
        AccessRights {
            start: 0,
            end: 1,
            ops: MEMOPS_ALL,
        },
    );
    assert!(invalid.is_err());
    assert_eq!(invalid.err().unwrap(), CapaError::InvalidOperation);
}

// ————————————————————————————— Carve & Alias —————————————————————————————— //

#[test]
fn counter_alias_carve_bug() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 10,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    // Alias a region then carve it and send both to the child.
    let r1 = engine
        .alias_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    let r2 = engine
        .carve_region(
            d0,
            r1,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();
    engine.send(d0, r1, d1_mgmt).unwrap();

    // This should not unlock a region.
    snap!("{}", regions(d1, engine));

    engine.send(d0, r2, d1_mgmt).unwrap();

    snap!(
        "{Region([0x0, 0x5 | P_RWXS]), Region([0x0, 0x5 | __RWXS])}",
        capas(d1, engine)
    );
    snap!("{[0x0, 0x5 | 1 (1 - 1 - 1 - 1)]}", regions(d1, engine));

    // Revoke the aliased (r1).
    engine.revoke(d1, LocalCapa::new(0)).unwrap();
    snap!("{}", capas(d1, engine));
    snap!("{}", regions(d1, engine));
}

#[test]
fn alias_then_carve() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 10,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Alias a region with less rights.
    let r1 = engine
        .alias_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MemOps::READ,
            },
        )
        .unwrap();
    // Carve that region. This should fail because it's not unique.
    // We try the carve on the root region.
    let carved_error = engine.carve_region(
        d0,
        r0,
        AccessRights {
            start: 0,
            end: 5,
            ops: MemOps::READ,
        },
    );
    assert!(carved_error.is_err());
    assert_eq!(carved_error.err().unwrap(), CapaError::InvalidOperation);

    // Check the state is untouched.
    snap!(
        "{Region([0x0, 0xa | PURWXS]), Region([0x0, 0x5 | __R___])}",
        capas(d0, engine)
    );
    snap!(
        "{[0x0, 0x5 | 2 (2 - 1 - 1 - 1)] -> [0x5, 0xa | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );

    // Now try to do a carve that overlaps partially at the head.
    let carved_error = engine.carve_region(
        d0,
        r0,
        AccessRights {
            start: 4,
            end: 6,
            ops: MemOps::READ,
        },
    );
    assert!(carved_error.is_err());
    assert_eq!(carved_error.err().unwrap(), CapaError::InvalidOperation);

    // Try to carve outside of alias.
    let carved_error = engine.carve_region(
        d0,
        r1,
        AccessRights {
            start: 4,
            end: 6,
            ops: MemOps::READ,
        },
    );
    assert!(carved_error.is_err());
    assert_eq!(carved_error.err().unwrap(), CapaError::InvalidOperation);

    // Now try to carve from r1 instead of r0.
    let r2 = engine
        .carve_region(
            d0,
            r1,
            AccessRights {
                start: 0,
                end: 5,
                ops: MemOps::READ,
            },
        )
        .unwrap();
    snap!(
        "{Region([0x0, 0xa | PURWXS]), Region([0x0, 0x5 | P_R___]), Region([0x0, 0x5 | __R___])}",
        capas(d0, engine)
    );
    snap!(
        "{[0x0, 0x5 | 2 (2 - 1 - 1 - 1)] -> [0x5, 0xa | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    //assert!(carved_error.is_err());
    //assert_eq!(carved_error.err().unwrap(), CapaError::InvalidOperation);

    // Carve r1 again.
    let carved_error = engine.carve_region(
        d0,
        r1,
        AccessRights {
            start: 1,
            end: 2,
            ops: MemOps::READ,
        },
    );

    assert!(carved_error.is_err());
    assert_eq!(carved_error.err().unwrap(), CapaError::InvalidOperation);

    // Alias r1 again.
    let alias_error = engine.alias_region(
        d0,
        r1,
        AccessRights {
            start: 1,
            end: 2,
            ops: MemOps::READ,
        },
    );
    assert!(alias_error.is_err());
    assert_eq!(alias_error.err().unwrap(), CapaError::InvalidOperation);

    // Send the alias->carved to a second domain.
    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();
    engine.send(d0, r2, d1_mgmt).unwrap();

    snap!(
        "{Region([0x0, 0xa | PURWXS]), Region([0x0, 0x5 | P_R___]), Management(2 | _)}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0xa | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    snap!("{Region([0x0, 0x5 | __R___])}", capas(d1, engine));
    snap!("{[0x0, 0x5 | 1 (1 - 0 - 0 - 0)]}", regions(d1, engine));

    // We started with an alias so d0 should still have it.
    engine.send(d0, r1, d1_mgmt).unwrap();
    snap!(
        "{Region([0x0, 0xa | PURWXS]), Management(2 | _)}",
        capas(d0, engine)
    );
    // All counters are at 1 because the carve was made from the alias and sent.
    snap!("{[0x0, 0xa | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    // One region that's carved from and alias and the carved one.
    // TODO(Charly) veryyyyy confusing though.
    snap!(
        "{Region([0x0, 0x5 | __R___]), Region([0x0, 0x5 | P_R___])}",
        capas(d1, engine)
    );
    snap!("{[0x0, 0x5 | 1 (1 - 0 - 0 - 0)]}", regions(d1, engine));
}

#[test]
fn cleanup() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    let r1 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0x200,
                end: 0x300,
                ops: MEMOPS_ALL | MemOps::CLEANUP,
            },
        )
        .unwrap();
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Region([0x200, 0x300 | _URWXS])}",
        capas(d0, engine)
    );

    // Drain updates
    while let Some(_) = engine.pop_update() {
        // Draining...
    }

    // Then revoke the region and expect a cleanup update
    engine.revoke(d0, r1).unwrap();
    snap!(
        "{PermissionUpdate(H(0, gen 0)), Cleanup([0x200, 0x300])}",
        updates(engine)
    );
}

// Disabled for now.
/*
#[test]
fn vital_regions() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine.create_manager_domain(permission::ALL).unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    let r1 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0x200,
                end: 0x300,
                ops: MEMOPS_ALL | MemOps::VITAL,
            },
        )
        .unwrap();
    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Region([0x200, 0x300 | _URWXS])}",
        capas(d0, engine)
    );

    // Create new domain and send region
    let d1 = engine.create_domain(d0).unwrap();
    let revok = engine.create_revoke_capa(d0, r1).unwrap();
    engine.send(d0, r1, d1).unwrap();
    let d1_capa = engine.get_domain_capa(d0, d1).unwrap();
    snap!("{Region([0x200, 0x300 | _URWXS])}", capas(d1_capa, engine));

    snap!(
        "{Region([0x0, 0x1000 | PURWXS]), Management(2 | _), RegionRevoke([0x200, 0x300 | CRWXS])}",
        capas(d0, engine)
    );
    engine.revoke(d0, revok).unwrap();
    let d1_capa = engine.get_domain_capa(d0, d1).unwrap();
    snap!("{}", capas(d1_capa, engine));
    snap!("{Region([0x0, 0x1000 | _URWXS])}", capas(d0, engine));
}*/

/// Test if the capa-engine frees resources appropriately.
/// If that is not the case we would get an out of memory error.
#[test]
fn free_resources() {
    const NB_ENCLAVES: usize = 200;
    const NB_REGIONS_PER_ENCLAVE: usize = 30;

    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Drain updates
    while let Some(_) = engine.pop_update() {
        // Draining...
    }

    // Record the capacity of each component
    let (domain_pool_capacity, region_pool_capacity, tracker_pool_capacity, update_capacity) =
        engine.get_capacity();

    for _ in 0..NB_ENCLAVES {
        // Create a new domain
        let d1 = engine.create_domain(d0).unwrap();

        // send a bunch of regions to that domain
        for _ in 0..NB_REGIONS_PER_ENCLAVE {
            let r = engine
                .alias_region(
                    d0,
                    r0,
                    AccessRights {
                        start: 0x200,
                        end: 0x300,
                        ops: MEMOPS_ALL | MemOps::CLEANUP,
                    },
                )
                .unwrap();
            engine.send(d0, r, d1).unwrap();
        }

        // Destroy domain, that should revoke all its regions
        engine.revoke(d0, d1).unwrap();
        // Drain updates
        while let Some(_) = engine.pop_update() {
            // Draining...
        }

        // The pools should have the same capacity after cleanup
        let (
            new_domain_pool_capacity,
            new_region_pool_capacity,
            new_tracker_pool_capacity,
            new_update_capacity,
        ) = engine.get_capacity();
        assert_eq!(
            domain_pool_capacity, new_domain_pool_capacity,
            "Memory leak in domain pool"
        );
        assert_eq!(
            region_pool_capacity, new_region_pool_capacity,
            "Memory leak in region pool"
        );
        assert_eq!(
            tracker_pool_capacity, new_tracker_pool_capacity,
            "Memory leak in tracker pool"
        );
        assert_eq!(
            update_capacity, new_update_capacity,
            "Memory leak in update buffer"
        );
    }
}

// —————————————————————————— Adversarial Enclave ——————————————————————————— //

#[test]
fn enclave_steal_via_alias() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 10,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    // Create an enclave region.
    let e_r0 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Create the enclave.
    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();
    engine
        .set_child_permission(
            d0,
            d1_mgmt,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::ALIAS | permission::monitor_inter_perm::CARVE,
        )
        .unwrap();

    // Get a revocation handle in the d0.
    let revoke_r0 = engine.create_revoke_capa(d0, e_r0).unwrap();

    // Send the region to the enclave.
    engine.send(d0, e_r0, d1_mgmt).unwrap();

    // Check the enclave has the capa.
    assert!(engine
        .get_region_capa(d1, LocalCapa::new(0))
        .unwrap()
        .is_some());

    // Let the enclave alias part of the memory.
    let _e_r1 = engine
        .alias_region(
            d1,
            LocalCapa::new(0),
            AccessRights {
                start: 1,
                end: 2,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    snap!(
        "{Region([0x0, 0x5 | PURWXS]), Region([0x1, 0x2 | __RWXS])}",
        capas(d1, engine)
    );
    snap!("{[0x0, 0x1 | 1 (1 - 1 - 1 - 1)] -> [0x1, 0x2 | 2 (2 - 2 - 2 - 2)] -> [0x2, 0x5 | 1 (1 - 1 - 1 - 1)]}", regions(d1, engine));
    // Check the parent only has the second part of the address space.
    snap!(
        "{Region([0x0, 0xa | PURWXS]), Management(2 | _), RegionRevoke([0x0, 0x5 | CRWXS])}",
        capas(d0, engine)
    );
    snap!("{[0x5, 0xa | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));

    // Now revoke with the handle we have.
    engine.revoke(d0, revoke_r0).unwrap();

    // The child should be left without any capas.
    snap!("{}", capas(d1, engine));
    // and without any region.
    snap!("{}", regions(d1, engine));
    // The parent should have access to the entire address space.
    snap!(
        "{Region([0x0, 0xa | _URWXS]), Management(2 | _)}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0xa | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
}

#[test]
fn enclave_steal_via_carve() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 10,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    // Create an enclave region.
    let e_r0 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Create the enclave.
    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();
    engine
        .set_child_permission(
            d0,
            d1_mgmt,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::ALIAS | permission::monitor_inter_perm::CARVE,
        )
        .unwrap();

    // Get a revocation handle in the d0.
    let revoke_r0 = engine.create_revoke_capa(d0, e_r0).unwrap();

    // Send the region to the enclave.
    engine.send(d0, e_r0, d1_mgmt).unwrap();

    // Check the enclave has the capa.
    assert!(engine
        .get_region_capa(d1, LocalCapa::new(0))
        .unwrap()
        .is_some());

    // Let the enclave carve part of the memory.
    let _e_r1 = engine
        .carve_region(
            d1,
            LocalCapa::new(0),
            AccessRights {
                start: 1,
                end: 2,
                ops: MemOps::READ,
            },
        )
        .unwrap();

    snap!(
        "{Region([0x0, 0x5 | PURWXS]), Region([0x1, 0x2 | _UR___])}",
        capas(d1, engine)
    );
    snap!("{[0x0, 0x1 | 1 (1 - 1 - 1 - 1)] -> [0x1, 0x2 | 1 (1 - 0 - 0 - 0)] -> [0x2, 0x5 | 1 (1 - 1 - 1 - 1)]}", regions(d1, engine));
    // Check the parent only has the second part of the address space.
    snap!(
        "{Region([0x0, 0xa | PURWXS]), Management(2 | _), RegionRevoke([0x0, 0x5 | CRWXS])}",
        capas(d0, engine)
    );
    snap!("{[0x5, 0xa | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));

    // Now revoke with the handle we have.
    engine.revoke(d0, revoke_r0).unwrap();

    // The child should be left without any capas.
    snap!("{}", capas(d1, engine));
    // and without any region.
    snap!("{}", regions(d1, engine));
    // The parent should have access to the entire address space.
    snap!(
        "{Region([0x0, 0xa | _URWXS]), Management(2 | _)}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0xa | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
}

#[test]
fn enclave_enclave_steal() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 10,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    // Create an enclave region.
    let e_r0 = engine
        .carve_region(
            d0,
            r0,
            AccessRights {
                start: 0,
                end: 5,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Create the enclave.
    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();
    engine
        .set_child_permission(
            d0,
            d1_mgmt,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::ALIAS
                | permission::monitor_inter_perm::CARVE
                | permission::monitor_inter_perm::SEND
                | permission::monitor_inter_perm::SPAWN,
        )
        .unwrap();

    // Get a revocation handle in the d0.
    let revoke_r0 = engine.create_revoke_capa(d0, e_r0).unwrap();

    // Send the region to the enclave.
    engine.send(d0, e_r0, d1_mgmt).unwrap();

    // Check the enclave has the capa.
    assert!(engine
        .get_region_capa(d1, LocalCapa::new(0))
        .unwrap()
        .is_some());

    // Let the enclave carve part of the memory.
    let e_e_r1 = engine
        .carve_region(
            d1,
            LocalCapa::new(0),
            AccessRights {
                start: 1,
                end: 2,
                ops: MemOps::READ,
            },
        )
        .unwrap();

    // Create another enclave from d1.
    let d2_mgmt = engine.create_domain(d1).unwrap();
    let d2 = engine.get_domain_capa(d1, d2_mgmt).unwrap();

    // Give the region to d2.
    engine.send(d1, e_e_r1, d2_mgmt).unwrap();

    snap!(
        "{Region([0x0, 0x5 | PURWXS]), Management(3 | _)}",
        capas(d1, engine)
    );
    snap!(
        "{[0x0, 0x1 | 1 (1 - 1 - 1 - 1)] -> [0x2, 0x5 | 1 (1 - 1 - 1 - 1)]}",
        regions(d1, engine)
    );
    // Check the parent only has the second part of the address space.
    snap!(
        "{Region([0x0, 0xa | PURWXS]), Management(2 | _), RegionRevoke([0x0, 0x5 | CRWXS])}",
        capas(d0, engine)
    );
    snap!("{[0x5, 0xa | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));

    // Check dom2
    snap!("{Region([0x1, 0x2 | _UR___])}", capas(d2, engine));
    snap!("{[0x1, 0x2 | 1 (1 - 0 - 0 - 0)]}", regions(d2, engine));

    // Now revoke with the handle we have.
    engine.revoke(d0, revoke_r0).unwrap();

    // The child should be left without any capas.
    snap!("{Management(3 | _)}", capas(d1, engine));
    // and without any region.
    snap!("{}", regions(d1, engine));

    snap!("{}", capas(d2, engine));
    snap!("{}", regions(d2, engine));
    // The parent should have access to the entire address space.
    snap!(
        "{Region([0x0, 0xa | _URWXS]), Management(2 | _)}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0xa | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
}

// ——————————————————————— Check domain capabilities ———————————————————————— //

#[test]
fn test_domain_capabilities() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();
    // Create initial region

    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x100,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Create d1.
    let d1_mgmt = engine.create_domain(d0).unwrap();
    let d1 = engine.get_domain_capa(d0, d1_mgmt).unwrap();
    // Send the r0 to d1.
    engine.send(d0, r0, d1_mgmt).unwrap();

    // D1 should be unable to create a domain.
    let err = engine.create_domain(d1);
    assert!(err.is_err());
    assert_eq!(err.err().unwrap(), CapaError::InsufficientPermissions);

    // Add the permission.
    engine
        .set_child_permission(
            d0,
            d1_mgmt,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::SPAWN,
        )
        .unwrap();
    // Try again.
    let d2_mgmt = engine.create_domain(d1).unwrap();
    let d2 = engine.get_domain_capa(d1, d2_mgmt).unwrap();

    // Should not be able to send a capa.
    let err = engine.send(d1, LocalCapa::new(0), d2_mgmt);
    assert!(err.is_err());
    assert_eq!(err.err().unwrap(), CapaError::InsufficientPermissions);

    // Add the permission.
    engine
        .set_child_permission(
            d0,
            d1_mgmt,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::SEND,
        )
        .unwrap();

    engine.send(d1, LocalCapa::new(0), d2_mgmt).unwrap();

    // Check the regions.
    snap!("{}", regions(d0, engine));
    snap!("{}", regions(d1, engine));
    snap!("{[0x0, 0x100 | 1 (1 - 1 - 1 - 1)]}", regions(d2, engine));

    // Impossible to revoke a root region..
    let err = engine.revoke(d2, LocalCapa::new(0));
    assert!(err.is_err());
}

// ——————————————————————————————— Scenarios ———————————————————————————————— //

//TODO
// ————————————————————————————— General Capas —————————————————————————————— //
#[test]
fn new_capa() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();

    // Create two new domains
    let d1 = engine.create_domain(d0).unwrap();
    let d2 = engine.create_domain(d0).unwrap();
    snap!("{Management(2 | _), Management(3 | _)}", capas(d0, engine));
    let d1_capa = engine.get_domain_capa(d0, d1).unwrap();
    let d2_capa = engine.get_domain_capa(d0, d2).unwrap();

    // Create initial region
    let r0 = engine
        .create_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x100,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    snap!(
        "{Management(2 | _), Management(3 | _), Region([0x0, 0x100 | _URWXS])}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0x100 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));

    // Alias and carve some regions
    let r1 = engine
        .alias_region(d0, r0, dummy_access(0x10, 0x20))
        .unwrap();
    snap!(
        "{Management(2 | _), Management(3 | _), Region([0x0, 0x100 | PURWXS]), Region([0x10, 0x20 | __RWXS])}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0x10 | 1 (1 - 1 - 1 - 1)] -> [0x10, 0x20 | 2 (2 - 2 - 2 - 2)] -> [0x20, 0x100 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));

    let r2 = engine
        .carve_region(d0, r0, dummy_access(0x30, 0x50))
        .unwrap();
    let r3 = engine
        .alias_region(d0, r2, dummy_access(0x40, 0x50))
        .unwrap();
    let r4 = engine
        .carve_region(d0, r0, dummy_access(0x60, 0x80))
        .unwrap();
    snap!(
        "{Management(2 | _), Management(3 | _), Region([0x0, 0x100 | PURWXS]), Region([0x10, 0x20 | __RWXS]), Region([0x30, 0x50 | PURWXS]), Region([0x40, 0x50 | __RWXS]), Region([0x60, 0x80 | _URWXS])}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0x10 | 1 (1 - 1 - 1 - 1)] -> [0x10, 0x20 | 2 (2 - 2 - 2 - 2)] -> [0x20, 0x40 | 1 (1 - 1 - 1 - 1)] -> [0x40, 0x50 | 2 (2 - 2 - 2 - 2)] -> [0x50, 0x100 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));

    // Create a revok capa
    let revoke_r1_capa = engine.create_revoke_capa(d0, r1).unwrap();
    snap!(
        "{Management(2 | _), Management(3 | _), Region([0x0, 0x100 | PURWXS]), Region([0x10, 0x20 | __RWXS]), Region([0x30, 0x50 | PURWXS]), Region([0x40, 0x50 | __RWXS]), Region([0x60, 0x80 | _URWXS]), RegionRevoke([0x10, 0x20 | _RWXS])}",
        capas(d0, engine)
    );

    // Send some of the regions
    engine.send(d0, r1, d1).unwrap();
    snap!(
        "{Management(2 | _), Management(3 | _), Region([0x0, 0x100 | PURWXS]), Region([0x30, 0x50 | PURWXS]), Region([0x40, 0x50 | __RWXS]), Region([0x60, 0x80 | _URWXS]), RegionRevoke([0x10, 0x20 | _RWXS])}",
        capas(d0, engine)
    );
    snap!("{[0x0, 0x40 | 1 (1 - 1 - 1 - 1)] -> [0x40, 0x50 | 2 (2 - 2 - 2 - 2)] -> [0x50, 0x100 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));
    snap!("{Region([0x10, 0x20 | __RWXS])}", capas(d1_capa, engine));
    snap!(
        "{[0x10, 0x20 | 1 (1 - 1 - 1 - 1)]}",
        regions(d1_capa, engine)
    );
    engine.send(d0, r2, d1).unwrap();
    snap!(
        "{Management(2 | _), Management(3 | _), Region([0x0, 0x100 | PURWXS]), Region([0x40, 0x50 | __RWXS]), Region([0x60, 0x80 | _URWXS]), RegionRevoke([0x10, 0x20 | _RWXS])}",
        capas(d0, engine)
    );
    snap!(
        "{[0x0, 0x30 | 1 (1 - 1 - 1 - 1)] -> [0x40, 0x100 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    snap!(
        "{Region([0x10, 0x20 | __RWXS]), Region([0x30, 0x50 | PURWXS])}",
        capas(d1_capa, engine)
    );
    snap!(
        "{[0x10, 0x20 | 1 (1 - 1 - 1 - 1)] -> [0x30, 0x50 | 1 (1 - 1 - 1 - 1)]}",
        regions(d1_capa, engine)
    );
    engine.send(d0, r3, d2).unwrap();
    snap!(
        "{Management(2 | _), Management(3 | _), Region([0x0, 0x100 | PURWXS]), Region([0x60, 0x80 | _URWXS]), RegionRevoke([0x10, 0x20 | _RWXS])}",
        capas(d0, engine)
    );
    snap!(
        "{[0x0, 0x30 | 1 (1 - 1 - 1 - 1)] -> [0x50, 0x100 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    snap!("{Region([0x40, 0x50 | __RWXS])}", capas(d2_capa, engine));
    snap!(
        "{[0x40, 0x50 | 1 (1 - 1 - 1 - 1)]}",
        regions(d2_capa, engine)
    );
    engine.send(d0, r4, d2).unwrap();
    snap!(
        "{Management(2 | _), Management(3 | _), Region([0x0, 0x100 | PURWXS]), RegionRevoke([0x10, 0x20 | _RWXS])}",
        capas(d0, engine)
    );
    snap!(
        "{[0x0, 0x30 | 1 (1 - 1 - 1 - 1)] -> [0x50, 0x60 | 1 (1 - 1 - 1 - 1)] -> [0x80, 0x100 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    snap!(
        "{Region([0x40, 0x50 | __RWXS]), Region([0x60, 0x80 | _URWXS])}",
        capas(d2_capa, engine)
    );
    snap!(
        "{[0x40, 0x50 | 1 (1 - 1 - 1 - 1)] -> [0x60, 0x80 | 1 (1 - 1 - 1 - 1)]}",
        regions(d2_capa, engine)
    );

    // Revoke some regions
    engine.revoke(d0, revoke_r1_capa).unwrap();
    snap!(
        "{Management(2 | _), Management(3 | _), Region([0x0, 0x100 | PURWXS])}",
        capas(d0, engine)
    );
    snap!("{Region([0x30, 0x50 | PURWXS])}", capas(d1_capa, engine));
    snap!(
        "{[0x30, 0x50 | 1 (1 - 1 - 1 - 1)]}",
        regions(d1_capa, engine)
    );
    snap!(
        "{[0x0, 0x30 | 1 (1 - 1 - 1 - 1)] -> [0x50, 0x60 | 1 (1 - 1 - 1 - 1)] -> [0x80, 0x100 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    engine.revoke(d1_capa, LocalCapa::new(1)).unwrap();
    snap!("{}", capas(d1_capa, engine));
    snap!("{}", regions(d1_capa, engine));
    snap!("{Region([0x60, 0x80 | _URWXS])}", capas(d2_capa, engine));
    snap!(
        "{[0x60, 0x80 | 1 (1 - 1 - 1 - 1)]}",
        regions(d2_capa, engine)
    );
    snap!(
        "{[0x0, 0x60 | 1 (1 - 1 - 1 - 1)] -> [0x80, 0x100 | 1 (1 - 1 - 1 - 1)]}",
        regions(d0, engine)
    );
    engine.revoke(d2_capa, LocalCapa::new(1)).unwrap();
    snap!("{}", capas(d2_capa, engine));
    snap!("{}", regions(d2_capa, engine));
    snap!("{[0x0, 0x100 | 1 (1 - 1 - 1 - 1)]}", regions(d0, engine));

    // Can't revoke root
    assert_eq!(
        engine.revoke(d0, LocalCapa::new(2)),
        Err(CapaError::InvalidOperation)
    );
}

// ————————————————————————————————— Utils —————————————————————————————————— //

fn regions(domain: Handle<Domain>, engine: &CapaEngine) -> RegionIterator {
    engine.get_domain_regions(domain).expect("Invalid domain")
}

fn capas(domain: Handle<Domain>, engine: &mut CapaEngine) -> String {
    let mut token = NextCapaToken::new();
    let mut buff = String::from("{");
    let mut is_first = true;

    while let Some((capa, new_token)) = engine.enumerate(domain, token) {
        if is_first {
            is_first = false;
        } else {
            buff.write_str(", ").unwrap();
        }
        buff.write_str(&format!("{:}", capa)).unwrap();
        token = new_token;
    }

    buff.write_str("}").unwrap();
    buff
}

fn updates(engine: &mut CapaEngine) -> String {
    let mut buff = String::from("{");
    let mut is_first = true;

    while let Some(update) = engine.pop_update() {
        if is_first {
            is_first = false;
        } else {
            buff.write_str(", ").unwrap();
        }
        buff.write_str(&format!("{}", update)).unwrap();
    }

    buff.write_str("}").unwrap();
    buff
}

fn dummy_access(start: usize, end: usize) -> AccessRights {
    AccessRights {
        start,
        end,
        ops: MEMOPS_ALL,
    }
}
