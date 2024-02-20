use vmx::bitmaps::SecondaryControls;
use vmx::{CPUID_ECX_X64_OSPKE, CPUID_ECX_X64_WAITPGK};

// Some filtering according to supported native features and virtualization ones.
// For example, 13th Gen Intel(R) Core(TM) i5-1345U support tpause and invpcid natively
// but does not allow the secondary control bit 26 to allow tpause in guest.
pub fn filter_tpause(
    in_eax: usize,
    in_ecx: usize,
    _out_eax: &mut usize,
    _out_ebx: &mut usize,
    out_ecx: &mut usize,
    _out_edx: &mut usize,
) {
    if (in_eax == 0x7 && in_ecx == 0x0)
        && (vmx::secondary_controls_capabilities()
            .expect("failed to get secondary capabilities")
            .bits()
            & SecondaryControls::ENABLE_USER_WAIT_PAUSE.bits()
            == 0)
        && (*out_ecx & (CPUID_ECX_X64_WAITPGK as usize) != 0)
    {
        // clear the cpuid tpause bit.
        *out_ecx = *out_ecx ^ !(CPUID_ECX_X64_WAITPGK as usize);
    }
}

pub fn filter_mpk(
    in_eax: usize,
    in_ecx: usize,
    _out_eax: &mut usize,
    _out_ebx: &mut usize,
    out_ecx: &mut usize,
    _out_edx: &mut usize,
) {
    if (in_eax == 0x7 && in_ecx == 0) && (*out_ecx & (CPUID_ECX_X64_OSPKE as usize) != 0) {
        *out_ecx = *out_ecx ^ !(CPUID_ECX_X64_OSPKE as usize);
    }
}
