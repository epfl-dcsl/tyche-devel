use vmx::fields::{VmcsField, VmcsFieldType};

/// Represents all the fields that cannot be set by a user when creating a new domain.
///
///TODO(aghosn): For the moment, we have a single disallow list.
///In the future, we should come up with some bitmap-style implementation to make
///this more flexible.
const DISALLOWED_FIELDS: [VmcsField; 30] = [
    /*Ept pointer related fields.*/
    VmcsField::EptPointer,
    VmcsField::EptPointerHigh,
    VmcsField::EptpListAddress,
    VmcsField::EptpListAddressHigh,
    /*Host fields.*/
    VmcsField::HostEsSelector,
    VmcsField::HostCsSelector,
    VmcsField::HostSsSelector,
    VmcsField::HostDsSelector,
    VmcsField::HostFsSelector,
    VmcsField::HostGsSelector,
    VmcsField::HostTrSelector,
    VmcsField::HostIa32Pat,
    VmcsField::HostIa32PatHigh,
    VmcsField::HostIa32Efer,
    VmcsField::HostIa32EferHigh,
    VmcsField::HostIa32PerfGlobalCtrl,
    VmcsField::HostIa32PerfGlobalCtrlHigh,
    VmcsField::HostIa32SysenterCs,
    VmcsField::HostCr0,
    VmcsField::HostCr3,
    VmcsField::HostCr4,
    VmcsField::HostFsBase,
    VmcsField::HostGsBase,
    VmcsField::HostTrBase,
    VmcsField::HostGdtrBase,
    VmcsField::HostIdtrBase,
    VmcsField::HostIa32SysenterEsp,
    VmcsField::HostIa32SysenterEip,
    VmcsField::HostRsp,
    VmcsField::HostRip,
];

const SELF_ALLOWED_FIELDS: [VmcsField; 16] = [
    VmcsField::GuestIa32Pat,
    VmcsField::GuestIa32PatHigh,
    VmcsField::GuestIa32Efer,
    VmcsField::GuestIa32EferHigh,
    VmcsField::GuestCr0,
    VmcsField::GuestCr3,
    VmcsField::GuestCr4,
    VmcsField::GuestCsSelector,
    VmcsField::GuestDsSelector,
    VmcsField::GuestEsSelector,
    VmcsField::GuestSsSelector,
    VmcsField::GuestTrSelector,
    VmcsField::GuestIdtrBase,
    VmcsField::GuestSysenterCs,
    VmcsField::GuestSysenterEsp,
    VmcsField::GuestSysenterEip,
];

/// API to select which fields are exposed.
pub struct FilteredFields {}

impl FilteredFields {
    pub fn is_valid(idx: usize, is_write: bool) -> bool {
        if let Some(value) = VmcsField::from_u32(idx as u32) {
            match DISALLOWED_FIELDS.iter().position(|item| *item == value) {
                Some(_) => return false,
                // Eliminate non-writable fields
                _ => return !(is_write && value.tpe() == VmcsFieldType::VmExitInformation),
            }
        }
        return false;
    }

    pub fn is_valid_self(field: VmcsField) -> bool {
        match SELF_ALLOWED_FIELDS.iter().position(|item| *item == field) {
            Some(_) => return true,
            _ => return false,
        }
    }
}
