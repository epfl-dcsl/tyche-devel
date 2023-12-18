#![no_main]

use capa_engine::config::NB_CAPAS_PER_DOMAIN;
use capa_engine::{permission, AccessRights, CapaEngine, Domain, Handle, LocalCapa, MEMOPS_ALL};
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::{arbitrary, fuzz_target};

type CapaIdx = u8;

#[derive(Arbitrary, Debug)]
pub enum Action {
    CreateDomain,
    Seal(CapaIdx),
    Send(CapaIdx, CapaIdx),
    Revoke(CapaIdx),
    CreateSwitch,
    SegmentRegion(CapaIdx, Access, Access),
}

#[derive(Arbitrary, Debug)]
pub struct Access {
    start: u8,
    end: u8,
}

struct State {
    current_domain: Handle<Domain>,
}

fuzz_target!(|actions: Vec<Action>| {
    fuzz(actions);
});

fn fuzz(actions: Vec<Action>) {
    let mut engine = CapaEngine::new();
    let root_domain = engine.create_manager_domain(permission::ALL).unwrap();
    let current_core = 0;
    engine
        .start_domain_on_core(root_domain, current_core)
        .unwrap();
    engine
        .create_root_region(
            root_domain,
            AccessRights {
                start: 0x0,
                end: 0x100,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    let mut s = State {
        current_domain: root_domain,
    };

    for action in &actions {
        match action {
            Action::CreateDomain => {
                engine.create_domain(s.current_domain).ok();
            }
            Action::Seal(idx) => {
                engine
                    .seal(s.current_domain, usize::MAX, as_capa(*idx))
                    .ok();
            }
            Action::Send(capa, to) => {
                engine
                    .send(s.current_domain, as_capa(*capa), as_capa(*to))
                    .ok();
            }
            Action::Revoke(capa) => {
                engine.revoke(s.current_domain, as_capa(*capa)).ok();
            }
            Action::CreateSwitch => {
                engine.create_switch(s.current_domain, current_core).ok();
            }
            Action::SegmentRegion(capa, left, right) => {
                engine
                    .segment_region(
                        s.current_domain,
                        as_capa(*capa),
                        AccessRights {
                            start: left.start as usize,
                            end: left.end as usize,
                            ops: MEMOPS_ALL,
                        },
                        AccessRights {
                            start: right.start as usize,
                            end: right.end as usize,
                            ops: MEMOPS_ALL,
                        },
                    )
                    .ok();
            }
        }
        apply_updates(&mut engine, &mut s);
    }
}

fn as_capa(idx: u8) -> LocalCapa {
    LocalCapa::new((idx as usize) % NB_CAPAS_PER_DOMAIN)
}

fn apply_updates(engine: &mut CapaEngine, s: &mut State) {
    while let Some(update) = engine.pop_update() {
        match update {
            capa_engine::Update::PermissionUpdate { .. } => (),
            capa_engine::Update::TlbShootdown { .. } => (),
            capa_engine::Update::RevokeDomain { .. } => (),
            capa_engine::Update::CreateDomain { .. } => (),
            capa_engine::Update::Switch { domain, .. } => {
                s.current_domain = domain;
            }
            capa_engine::Update::Trap { manager, .. } => {
                s.current_domain = manager;
            }
            capa_engine::Update::UpdateTraps { .. } => (),
        }
    }
}
