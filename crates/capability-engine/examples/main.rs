use capa_engine::{permission, AccessRights, CapaEngine, Domain, Handle, MemOps};
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Trace)
        // .with_level(log::LevelFilter::Info)
        .with_colors(true)
        .init()
        .unwrap();

    foo();
}

#[allow(unused)]
fn bar() {
    let mut pool = capa_engine::RegionTracker::new();

    pool.add_region(0x200, 0x300, MEMOPS_ALL, None).unwrap();
    println!("{}", &pool);
    pool.add_region(0x300, 0x400, MEMOPS_ALL, None).unwrap();
    println!("{}", &pool);
    pool.add_region(0x100, 0x500, MEMOPS_ALL, None).unwrap();
    println!("{}", &pool);
    pool.remove_region(0x200, 0x400, MEMOPS_ALL).unwrap();
    println!("{}", &pool);
}

#[allow(unused)]
fn foo() {
    let mut engine = CapaEngine::new();
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    let region = engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0,
                end: 0x1000,
                ops: MemOps::NONE,
                alias: None,
            },
        )
        .unwrap();
    display(&engine);
    display_domain(domain, &engine);

    let (reg2, _reg3) = engine
        .segment_region(
            domain,
            region,
            AccessRights {
                start: 0,
                end: 0x200,
                ops: MemOps::NONE,
                alias: None,
            },
            AccessRights {
                start: 0x300,
                end: 0x1000,
                ops: MemOps::NONE,
                alias: None,
            },
        )
        .unwrap();
    display(&engine);
    display_domain(domain, &engine);
    let (_reg4, _reg5) = engine
        .segment_region(
            domain,
            reg2,
            AccessRights {
                start: 0,
                end: 0x50,
                ops: MemOps::NONE,
                alias: None,
            },
            AccessRights {
                start: 0x50,
                end: 0x200,
                ops: MemOps::NONE,
                alias: None,
            },
        )
        .unwrap();
    display(&engine);
    display_domain(domain, &engine);

    let dom2 = engine.create_domain(domain).unwrap();
    engine.set_child_config(
        domain,
        dom2,
        capa_engine::Bitmaps::PERMISSION,
        permission::SPAWN,
    );
    let domain2 = engine.get_domain_capa(domain, dom2).unwrap();
    engine.send(domain, reg2, dom2);
    display(&engine);
    display_domain(domain, &engine);
    display_domain(domain2, &engine);

    engine.create_domain(domain2).unwrap();
    engine.revoke_domain(domain2);
    display(&engine);
    display_domain(domain, &engine);

    engine.restore_region(domain, region);
    display(&engine);
    display_domain(domain, &engine);
}

fn display(_engine: &CapaEngine) {
    // println!("{}", engine.get_regions());
}

fn display_domain(handle: Handle<Domain>, engine: &CapaEngine) {
    let domain = &engine[handle];
    println!(
        "Domain {} {}",
        domain.id(),
        &engine.get_domain_regions(handle).expect("Invalid domain")
    );
    print!("         {{");
    let mut first = true;
    for area in engine
        .get_domain_permissions(handle)
        .expect("Invalid domain")
    {
        if first {
            first = false;
        } else {
            print!(" -> ");
        }
        print!("{}", area);
    }
    println!("}}");
}
