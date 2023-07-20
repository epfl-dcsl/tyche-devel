use std::fmt::Write;

use capa_engine::{
    permission, AccessRights, CapaEngine, Domain, Handle, MemOps, NextCapaToken, RegionTracker,
    MEMOPS_ALL,
};

/// Snapshot testing
///
/// Checks that the given struct matches the provided snap!shot.
macro_rules! snap {
    ($snap:expr, $item:expr $(,)?) => {
        assert_eq!($snap, &format!("{}", $item));
    };
}

// ——————————————————————————————— Scenarios ———————————————————————————————— //

/// This scenario exercise multiple part of the engine: creating domains and region, sending and
/// revoking.
#[test]
fn scenario_1() {
    let mut engine = CapaEngine::new();

    // Create an initial domain with range 0x0 to 0x1000
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    let region = engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x1000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x1000 | AC____])}",
        capas(domain, &mut engine)
    );
    snap!(
        "{PermissionUpdate(H(0, gen 0)), CreateDomain(H(0, gen 0))}",
        updates(&mut engine)
    );

    // Duplicate the initial range into two regions
    let (reg2, _reg3) = engine
        .segment_region(
            domain,
            region,
            AccessRights {
                start: 0,
                end: 0x200,
                ops: MemOps::NONE,
            },
            AccessRights {
                start: 0x300,
                end: 0x1000,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x200 | 1 (0 - 0 - 0 - 0)] -> [0x300, 0x1000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine),
    );
    snap!(
        "{Region([0x0, 0x1000 | _C____]), Region([0x0, 0x200 | AC____]), Region([0x300, 0x1000 | AC____])}",
        capas(domain, &mut engine),
    );
    snap!("{PermissionUpdate(H(0, gen 0))}", updates(&mut engine));

    // Duplicate again
    let (_reg4, _reg5) = engine
        .segment_region(
            domain,
            reg2,
            AccessRights {
                start: 0,
                end: 0x50,
                ops: MemOps::NONE,
            },
            AccessRights {
                start: 0x50,
                end: 0x200,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x200 | 1 (0 - 0 - 0 - 0)] -> [0x300, 0x1000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine),
    );
    snap!(
        "{Region([0x0, 0x1000 | _C____]), Region([0x0, 0x200 | _C____]), Region([0x300, 0x1000 | AC____]), Region([0x0, 0x50 | AC____]), Region([0x50, 0x200 | AC____])}",
        capas(domain, &mut engine)
    );
    snap!("{}", updates(&mut engine));

    // Create a new domain and send the inactive region there
    let dom2 = engine.create_domain(domain).unwrap();
    let domain2 = engine.get_domain_capa(domain, dom2).unwrap();
    engine.send(domain, reg2, dom2).unwrap();
    snap!(
        "{[0x0, 0x200 | 1 (0 - 0 - 0 - 0)] -> [0x300, 0x1000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine),
    );
    snap!("{}", regions(domain2, &engine));
    snap!(
        "{Region([0x0, 0x1000 | _C____]), Region([0x300, 0x1000 | AC____]), Region([0x0, 0x50 | AC____]), Region([0x50, 0x200 | AC____]), Management(2 | _)}",
        capas(domain, &mut engine)
    );
    snap!(
        "{Region([0x0, 0x200 | _C____])}",
        capas(domain2, &mut engine)
    );
    snap!("{CreateDomain(H(1, gen 0))}", updates(&mut engine));

    // Revoke the domain owning the active region. This invalidates regions from the first domain
    engine.revoke_domain(domain2).unwrap();
    snap!(
        "{[0x300, 0x1000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine),
    );
    snap!(
        "{Region([0x0, 0x1000 | _C____]), Region([0x300, 0x1000 | AC____])}",
        capas(domain, &mut engine)
    );
    snap!(
        "{PermissionUpdate(H(0, gen 0)), PermissionUpdate(H(0, gen 0)), RevokeDomain(H(1, gen 0))}",
        updates(&mut engine)
    );

    // Restore the initial region
    engine.restore_region(domain, region).unwrap();
    snap!(
        "{[0x0, 0x1000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine),
    );
    snap!(
        "{Region([0x0, 0x1000 | AC____])}",
        capas(domain, &mut engine)
    );
    snap!("{PermissionUpdate(H(0, gen 0))}", updates(&mut engine));
}

#[test]
fn scenario_2() {
    let mut engine = CapaEngine::new();
    let core = 0;

    // Create an initial domain with range 0x0 to 0x1000
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    engine.start_domain_on_core(domain, core).unwrap();
    let region = engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x1000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x1000 | AC____])}",
        capas(domain, &mut engine)
    );
    snap!(
        "{PermissionUpdate(H(0, gen 0)), TlbShootdown(0), CreateDomain(H(0, gen 0))}",
        updates(&mut engine)
    );

    // Duplicate the initial range into two regions
    let (reg2, _reg3) = engine
        .segment_region(
            domain,
            region,
            AccessRights {
                start: 0,
                end: 0x200,
                ops: MemOps::NONE,
            },
            AccessRights {
                start: 0x300,
                end: 0x1000,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x200 | 1 (0 - 0 - 0 - 0)] -> [0x300, 0x1000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine),
    );
    snap!(
        "{Region([0x0, 0x1000 | _C____]), Region([0x0, 0x200 | AC____]), Region([0x300, 0x1000 | AC____])}",
        capas(domain, &mut engine),
    );
    snap!(
        "{PermissionUpdate(H(0, gen 0)), TlbShootdown(0)}",
        updates(&mut engine)
    );

    // Create a new domain and send a region there
    let dom2 = engine.create_domain(domain).unwrap();
    let domain2 = engine.get_domain_capa(domain, dom2).unwrap();
    engine.send(domain, reg2, dom2).unwrap();
    snap!(
        "{[0x300, 0x1000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine),
    );
    snap!(
        "{[0x0, 0x200 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain2, &engine)
    );
    snap!(
        "{Region([0x0, 0x1000 | _C____]), Region([0x300, 0x1000 | AC____]), Management(2 | _)}",
        capas(domain, &mut engine)
    );
    snap!(
        "{Region([0x0, 0x200 | AC____])}",
        capas(domain2, &mut engine)
    );
    snap!(
        "{PermissionUpdate(H(1, gen 0)), PermissionUpdate(H(0, gen 0)), TlbShootdown(0), CreateDomain(H(1, gen 0))}",
        updates(&mut engine)
    );

    // Seal domain
    engine
        .set_child_config(domain, dom2, capa_engine::Bitmaps::TRAP, 0)
        .unwrap();
    engine
        .set_child_config(domain, dom2, capa_engine::Bitmaps::PERMISSION, 0)
        .unwrap();
    engine
        .set_child_config(domain, dom2, capa_engine::Bitmaps::CORE, 1)
        .unwrap();
    engine
        .set_child_config(domain, dom2, capa_engine::Bitmaps::SWITCH, 0)
        .unwrap();

    let switch = engine.seal(domain, core, dom2).unwrap();
    // Second seal should fail
    assert!(engine.seal(domain, core, dom2).is_err());

    // Switch
    engine.switch(domain, core, switch).unwrap();
}

#[test]
fn scenario_3() {
    let mut engine = CapaEngine::new();
    let core = 0;

    // Create initial domain and range memory 0x0 to 0x10000.
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    let _ctx = engine.start_domain_on_core(domain, 0).unwrap();
    let region = engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0x0,
                end: 0x10000,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    // Carve a hole into the region: 0x0 -- 0x1000 | 0x1000 -- 0x2000 | 0x2000 -- 0x10000
    let (_reg0, reg_chg) = engine
        .segment_region(
            domain,
            region,
            AccessRights {
                start: 0x0,
                end: 0x1000,
                ops: MemOps::NONE,
            },
            AccessRights {
                start: 0x1000,
                end: 0x10000,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    let (reg1, _reg2) = engine
        .segment_region(
            domain,
            reg_chg,
            AccessRights {
                start: 0x1000,
                end: 0x2000,
                ops: MemOps::NONE,
            },
            AccessRights {
                start: 0x2000,
                end: 0x10000,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    // mimic the null segment trick.
    let (_reg_empty, reg_to_give) = engine
        .segment_region(
            domain,
            reg1,
            AccessRights {
                start: 0x1000,
                end: 0x1000,
                ops: MemOps::NONE,
            },
            AccessRights {
                start: 0x1000,
                end: 0x2000,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    // Create a new domain and send the region.
    let encl = engine.create_domain(domain).unwrap();
    let enclave = engine.get_domain_capa(domain, encl).unwrap();
    engine.send(domain, reg_to_give, encl).unwrap();

    // Seal domain.
    engine
        .set_child_config(domain, encl, capa_engine::Bitmaps::TRAP, 0)
        .unwrap();
    engine
        .set_child_config(domain, encl, capa_engine::Bitmaps::PERMISSION, 0)
        .unwrap();
    engine
        .set_child_config(domain, encl, capa_engine::Bitmaps::CORE, 1)
        .unwrap();
    engine
        .set_child_config(domain, encl, capa_engine::Bitmaps::SWITCH, 0)
        .unwrap();
    let _ = engine.seal(domain, core, encl).unwrap();
    snap!(
        "{[0x1000, 0x2000 | 1 (0 - 0 - 0 - 0)]}",
        regions(enclave, &engine)
    );
    // Now delete the enclaves' region.
    engine.revoke(domain, reg1).unwrap();
    snap!("{}", regions(enclave, &engine));
    engine.revoke(domain, encl).unwrap();
    // Test cleanup
    engine.revoke(domain, region).unwrap();
    snap!(
        "{[0x0, 0x10000 | 1 (0 - 0 - 0 - 0)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x10000 | AC____])}",
        capas(domain, &mut engine)
    );
}

#[test]
fn access_rights_test() {
    let mut engine = CapaEngine::new();
    let core = 0;
    // Create initial domain.
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    let _ctx = engine.start_domain_on_core(domain, core).unwrap();
    let region = engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0,
                end: 0x100000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    snap!(
        "{[0x0, 0x100000 | 1 (1 - 1 - 1 - 1)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x100000 | ACRWXS])}",
        capas(domain, &mut engine)
    );
    // Try the null segment trick.
    let (_reg1, _reg2) = engine
        .segment_region(
            domain,
            region,
            AccessRights {
                start: 0,
                end: 0,
                ops: MEMOPS_ALL,
            },
            AccessRights {
                start: 0,
                end: 0x100000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    snap!(
        "{[0x0, 0x100000 | 1 (1 - 1 - 1 - 1)]}",
        regions(domain, &engine)
    );
    snap!("{Region([0x0, 0x100000 | _CRWXS]), Region([0x0, 0x0 | _CRWXS]), Region([0x0, 0x100000 | ACRWXS])}", capas(domain, &mut engine));

    // Now revoke the original capability.
    engine.revoke(domain, region).unwrap();
    snap!(
        "{[0x0, 0x100000 | 1 (1 - 1 - 1 - 1)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x100000 | ACRWXS])}",
        capas(domain, &mut engine)
    );

    // Now try a duplicate.
    let (_reg1, _reg2) = engine
        .segment_region(
            domain,
            region,
            AccessRights {
                start: 0,
                end: 0x100000,
                ops: MEMOPS_ALL,
            },
            AccessRights {
                start: 0,
                end: 0x100000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x100000 | 2 (2 - 2 - 2 - 2)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x100000 | _CRWXS]), Region([0x0, 0x100000 | A_RWXS]), Region([0x0, 0x100000 | A_RWXS])}",
        capas(domain, &mut engine)
    );
    // revoke.
    engine.revoke(domain, region).unwrap();
    snap!(
        "{[0x0, 0x100000 | 1 (1 - 1 - 1 - 1)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x100000 | ACRWXS])}",
        capas(domain, &mut engine)
    );
    // Now with different access rights.
    let (reg1, _reg2) = engine
        .segment_region(
            domain,
            region,
            AccessRights {
                start: 0,
                end: 0x100000,
                ops: MemOps::READ,
            },
            AccessRights {
                start: 0,
                end: 0x100000,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x100000 | 2 (2 - 1 - 1 - 1)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x100000 | _CRWXS]), Region([0x0, 0x100000 | A_RWXS]), Region([0x0, 0x100000 | A_R___])}",
        capas(domain, &mut engine)
    );
    // Now pause the read one.
    let (_, _) = engine
        .segment_region(
            domain,
            reg1,
            AccessRights {
                start: 0,
                end: 0,
                ops: MemOps::NONE,
            },
            AccessRights {
                start: 0,
                end: 0,
                ops: MemOps::NONE,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x100000 | 1 (1 - 1 - 1 - 1)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x100000 | _CRWXS]), Region([0x0, 0x100000 | A_RWXS]), Region([0x0, 0x100000 | __R___]), Region([0x0, 0x0 | ______]), Region([0x0, 0x0 | ______])}",
        capas(domain, &mut engine)
    );
    // Cleanup everything from a higher capa.
    engine.revoke(domain, region).unwrap();
    snap!(
        "{[0x0, 0x100000 | 1 (1 - 1 - 1 - 1)]}",
        regions(domain, &engine)
    );
    snap!(
        "{Region([0x0, 0x100000 | ACRWXS])}",
        capas(domain, &mut engine)
    );
}

// ————————————————————————————————— Utils —————————————————————————————————— //

fn regions(domain: Handle<Domain>, engine: &CapaEngine) -> &RegionTracker {
    engine[domain].regions()
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
