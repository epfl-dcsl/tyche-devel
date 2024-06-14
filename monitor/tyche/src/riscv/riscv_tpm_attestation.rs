use attestation::signature::EnclaveReport;

pub fn pass_attestation(report: &EnclaveReport, call_nb: usize) -> (isize, isize, [usize; 5]) {
    let mut arr: [usize; 5] = [0; 5];
    let mut val0: isize = 0;
    let mut val1: isize = 0;
    let mut val2: usize = 0;
    let mut val3: usize = 0;
    let mut val4: usize = 0;
    let mut val5: usize = 0;
    let mut val6: usize = 0;

    match call_nb {
        0 => {
            val1 = isize::from_le_bytes(report.public_key.as_slice()[0..8].try_into().unwrap());
            val2 = usize::from_le_bytes(report.public_key.as_slice()[8..16].try_into().unwrap());
            val3 = usize::from_le_bytes(report.public_key.as_slice()[16..24].try_into().unwrap())
                as usize;
            val4 = usize::from_le_bytes(report.public_key.as_slice()[24..32].try_into().unwrap())
                as usize;
            val5 = usize::from_le_bytes(
                report.signed_enclave_data.as_slice()[0..8]
                    .try_into()
                    .unwrap(),
            ) as usize;
            val6 = usize::from_le_bytes(
                report.signed_enclave_data.as_slice()[8..16]
                    .try_into()
                    .unwrap(),
            ) as usize;
        }
        1 => {
            val1 = isize::from_le_bytes(
                report.signed_enclave_data.as_slice()[16..24]
                    .try_into()
                    .unwrap(),
            );
            val2 = usize::from_le_bytes(
                report.signed_enclave_data.as_slice()[24..32]
                    .try_into()
                    .unwrap(),
            );
            val3 = usize::from_le_bytes(
                report.signed_enclave_data.as_slice()[32..40]
                    .try_into()
                    .unwrap(),
            );
            val4 = usize::from_le_bytes(
                report.signed_enclave_data.as_slice()[40..48]
                    .try_into()
                    .unwrap(),
            );
            val5 = usize::from_le_bytes(
                report.signed_enclave_data.as_slice()[48..56]
                    .try_into()
                    .unwrap(),
            );
            val6 = usize::from_le_bytes(
                report.signed_enclave_data.as_slice()[56..64]
                    .try_into()
                    .unwrap(),
            );
        }
        2..=9 => {
            let mut offset: usize = (call_nb - 2) * 6 * 8;
            let mut upper_bound: usize = offset + 8;
            val1 = isize::from_le_bytes(
                report.tpm_signature.as_slice()[offset..upper_bound]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val2 = usize::from_le_bytes(
                report.tpm_signature.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val3 = usize::from_le_bytes(
                report.tpm_signature.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val4 = usize::from_le_bytes(
                report.tpm_signature.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val5 = usize::from_le_bytes(
                report.tpm_signature.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val6 = usize::from_le_bytes(
                report.tpm_signature.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
        }
        10..=17 => {
            let mut offset: usize = (call_nb - 10) * 6 * 8;
            val1 = isize::from_le_bytes(
                report.tpm_modulus.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val2 = usize::from_le_bytes(
                report.tpm_modulus.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val3 = usize::from_le_bytes(
                report.tpm_modulus.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val4 = usize::from_le_bytes(
                report.tpm_modulus.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val5 = usize::from_le_bytes(
                report.tpm_modulus.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val6 = usize::from_le_bytes(
                report.tpm_modulus.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
        }
        18 | 19 => {
            let mut offset: usize = (call_nb - 18) * 6 * 8;
            val1 = isize::from_le_bytes(
                report.tpm_attestation.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val2 = usize::from_le_bytes(
                report.tpm_attestation.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val3 = usize::from_le_bytes(
                report.tpm_attestation.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val4 = usize::from_le_bytes(
                report.tpm_attestation.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val5 = usize::from_le_bytes(
                report.tpm_attestation.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
            offset += 8;
            val6 = usize::from_le_bytes(
                report.tpm_attestation.as_slice()[offset..offset + 8]
                    .try_into()
                    .unwrap(),
            );
        }
        20 => {
            val1 = isize::from_le_bytes(
                report.tpm_attestation.as_slice()[96..104]
                    .try_into()
                    .unwrap(),
            );
            val2 = usize::from_le_bytes(
                report.tpm_attestation.as_slice()[104..112]
                    .try_into()
                    .unwrap(),
            );
            val3 = usize::from_le_bytes(
                report.tpm_attestation.as_slice()[112..120]
                    .try_into()
                    .unwrap(),
            );
            val4 = usize::from_le_bytes(
                report.tpm_attestation.as_slice()[120..128]
                    .try_into()
                    .unwrap(),
            );
            val5 = usize::from(report.tpm_attestation[128]);
        }
        _ => {
            log::trace!("Attestation error");
            val0 = 1;
        }
    };
    if val0 == 0 {
        arr[0] = val2;
        arr[1] = val3;
        arr[2] = val4;
        arr[3] = val5;
        arr[4] = val6;
    }
    (val0, val1, arr)
}
