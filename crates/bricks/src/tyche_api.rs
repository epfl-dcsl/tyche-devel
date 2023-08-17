pub struct TycheCallArgs {
    vmmcall: u32,

    arg_1: usize,
    arg_2: usize,
    arg_3: usize,
    arg_4: usize,
    arg_5: usize,
    arg_6: usize,

    // Results.
    value_1: usize,
    value_2: usize,
    value_3: usize,
    value_4: usize,
    value_5: usize,
    value_6: usize,
}

pub fn call_tyche(args: &mut TycheCallArgs) {
    // TODO
}
