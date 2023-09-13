use x86_64::registers::segmentation::{Segment, SegmentSelector, DS, ES, SS};

static mut DS_REG: Option<SegmentSelector> = None;
static mut ES_REG: Option<SegmentSelector> = None;
static mut SS_REG: Option<SegmentSelector> = None;
pub fn bricks_save_segments() {
    unsafe {
        DS_REG = Some(DS::get_reg());
        ES_REG = Some(ES::get_reg());
        SS_REG = Some(SS::get_reg());
    }
}

pub fn bricks_restore_segments() {
    unsafe {
        if let Some(ds_reg) = DS_REG {
            DS::set_reg(ds_reg);
        }
        if let Some(es_reg) = ES_REG {
            ES::set_reg(es_reg);
        }
        if let Some(ss_reg) = SS_REG {
            SS::set_reg(ss_reg);
        }
    }
}
