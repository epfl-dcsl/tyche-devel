use attest_client::{Context, MemOps};
use capa_engine::permission;

fn main() {
    println!("Hello, World!");

    let mut ctx = Context::new();
    let ops = MemOps::all();
    let r0 = ctx.root(0, 0x100, ops);
    let r1 = ctx.alias(r0, 0x10, 0x20, ops);
    let r2 = ctx.carve(r0, 0x30, 0x50, ops);
    let r3 = ctx.alias(r2, 0x40, 0x50, ops);
    let r4 = ctx.carve(r0, 0x60, 0x80, ops);
    let d0 = ctx.add_domain(0, permission::monitor_inter_perm::ALL);
    let d1 = ctx.add_domain(1, permission::monitor_inter_perm::ALL);
    let d2 = ctx.add_domain(2, permission::monitor_inter_perm::NONE);
    ctx[d0].add(r0).add(d1);
    ctx[d1].add(r1).add(r2).add(d2);
    ctx[d2].add(r3).add(r4);

    println!("{:?}", &ctx);
}
