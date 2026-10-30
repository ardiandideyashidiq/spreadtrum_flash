//! AVB disabling and CVE payload merger matching C common.c.

use crate::dhtb::{SIZEOF_SPRDSIGNEDIMAGEHEADER, SIZEOF_SYS_IMG_HEADER};
use std::fs;
use std::io::{self, Error, ErrorKind};

/// Patches `tos` to disable AVB verification. Writes result to `tos-noavb`.
pub fn dis_avb(filename: &str) -> io::Result<bool> {
    let mut mem = fs::read(filename)?;
    let size = mem.len();
    if size < SIZEOF_SYS_IMG_HEADER {
        return Err(Error::new(ErrorKind::InvalidData, "file too small"));
    }

    let m_img_size = u32::from_le_bytes(mem[0x30..0x34].try_into().unwrap()) as usize;
    let img_hdr_offset = m_img_size + 0x200;
    if img_hdr_offset + SIZEOF_SPRDSIGNEDIMAGEHEADER > size {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "image header out of bounds",
        ));
    }

    let payload_offset = u64::from_le_bytes(
        mem[img_hdr_offset + 16..img_hdr_offset + 24]
            .try_into()
            .unwrap(),
    );
    if payload_offset != SIZEOF_SYS_IMG_HEADER as u64 {
        eprintln!("image already patched");
        return Ok(false);
    }

    let mut pmov = [0usize; 3];
    let mut mov_count = 0;
    let mut last_start_pos = 0;
    let mut start_pos = 0;

    let mut i = 0x200;
    while i + 4 <= size {
        let current = u32::from_le_bytes(mem[i..i + 4].try_into().unwrap());
        if current == 0xD65F03C0 || (current & 0xFF00FFFF) == 0xA8007BFD {
            last_start_pos = 0;
            start_pos = 0;
        } else if (current & 0xFF00FFFF) == 0xA9007BFD {
            if start_pos != 0 {
                last_start_pos = start_pos;
            }
            start_pos = i;
        } else if start_pos != 0 {
            let mut ldp_count = 0;
            let mut m = 0;
            while m < 20 && i + m + 4 <= size {
                if mem[i + m + 3] == 0xA9 {
                    ldp_count += 1;
                } else {
                    break;
                }
                m += 4;
            }
            if ldp_count == 5 {
                let mut ret_flag = 0;
                let mut m = 24;
                while m < 32 && i + m + 4 <= size {
                    let cur_ret = u32::from_le_bytes(mem[i + m..i + m + 4].try_into().unwrap());
                    if cur_ret == 0xD65F03C0 {
                        ret_flag += 1;
                    }
                    m += 4;
                }
                if ret_flag != 0 && i >= 7 {
                    let check_u16 = u16::from_le_bytes(mem[i - 4..i - 2].try_into().unwrap());
                    let check_u8 = mem[i - 7];
                    if check_u16 == 0x3E0 && check_u8 == 0x3 {
                        if start_pos > i && last_start_pos != 0 {
                            start_pos = last_start_pos;
                        }
                        let mut count1 = 0;
                        let mut count2 = 0;
                        let mut m = start_pos;
                        while m < i && m + 4 <= size {
                            let top16 = u32::from_le_bytes(mem[m..m + 4].try_into().unwrap()) >> 16;
                            if top16 == 0x9400 {
                                count1 += 1;
                            } else if top16 == 0xb400 {
                                count2 += 1;
                            }
                            m += 4;
                        }
                        if count1 != 0 && count2 != 0 && count1 + count2 > 2 {
                            eprintln!("detected mov at 0x{:x}", i - 4);
                            if mov_count < 3 {
                                pmov[mov_count] = i - 4;
                                mov_count += 1;
                            } else {
                                pmov[0] = pmov[1];
                                pmov[1] = pmov[2];
                                pmov[2] = i - 4;
                            }
                        }
                    }
                }
            }
        }
        i += 4;
    }

    if mov_count < 2 {
        eprintln!("dis_avb: skip saving!!!");
        return Ok(false);
    }

    let patch_idx = if mov_count > 2 {
        if (pmov[2] as isize) - 2 * (pmov[1] as isize) + (pmov[0] as isize) > 0 {
            1
        } else {
            2
        }
    } else {
        mov_count - 1
    };

    let patch_pos = pmov[patch_idx];
    eprintln!("patch mov at 0x{:x}", patch_pos);
    mem[patch_pos..patch_pos + 4].copy_from_slice(&0x52800000u32.to_le_bytes());

    fs::write("tos-noavb", &mem)?;
    Ok(true)
}

/// Merges signed image and modified unsigned image for CVE bypass.
pub fn bsp_cve_2img(
    signed_img_name: &str,
    unsigned_img_name: &str,
    merged_img_name: &str,
) -> io::Result<bool> {
    let signed_img = fs::read(signed_img_name)?;
    let mut modified_img = fs::read(unsigned_img_name)?;

    if signed_img.len() < SIZEOF_SYS_IMG_HEADER {
        return Err(Error::new(ErrorKind::InvalidData, "signed img too small"));
    }

    // Pad modified_img to multiple of 16
    let orig_mod_size = modified_img.len();
    let mod_padded_size = orig_mod_size.div_ceil(16) * 16;
    modified_img.resize(mod_padded_size, 0);

    let mut actual_mod_size = mod_padded_size;
    let mut mod_payload_offset = 0;

    let mod_magic = if modified_img.len() >= 4 {
        u32::from_le_bytes(modified_img[0..4].try_into().unwrap())
    } else {
        0
    };
    let mod_img_size_field = if modified_img.len() >= 0x34 {
        u32::from_le_bytes(modified_img[0x30..0x34].try_into().unwrap()) as usize
    } else {
        0
    };

    if mod_magic == 0x42544844 && mod_img_size_field != 0 {
        actual_mod_size = mod_img_size_field;
        mod_payload_offset = SIZEOF_SYS_IMG_HEADER;
    }

    let signed_hdr_bytes = &signed_img[..SIZEOF_SYS_IMG_HEADER];
    let signed_img_size_field =
        u32::from_le_bytes(signed_hdr_bytes[0x30..0x34].try_into().unwrap()) as usize;
    let signed_img_body = &signed_img[SIZEOF_SYS_IMG_HEADER..];

    let mut output =
        Vec::with_capacity(SIZEOF_SYS_IMG_HEADER + actual_mod_size + signed_img_body.len());

    // Update header copy
    let mut updated_hdr = signed_hdr_bytes.to_vec();
    let new_m_img_size = (signed_img_size_field + actual_mod_size) as u32;
    updated_hdr[0x30..0x34].copy_from_slice(&new_m_img_size.to_le_bytes());

    // In signed_img_body, the sprdsignedimageheader is located at offset signed_img_size_field (since body starts at 0x200)
    let mut updated_body = signed_img_body.to_vec();
    let sprdsigned_hdr_offset = signed_img_size_field;
    if sprdsigned_hdr_offset + SIZEOF_SPRDSIGNEDIMAGEHEADER <= updated_body.len() {
        let payload_offset = u64::from_le_bytes(
            updated_body[sprdsigned_hdr_offset + 16..sprdsigned_hdr_offset + 24]
                .try_into()
                .unwrap(),
        );
        let cert_offset = u64::from_le_bytes(
            updated_body[sprdsigned_hdr_offset + 32..sprdsigned_hdr_offset + 40]
                .try_into()
                .unwrap(),
        );

        let new_payload_offset = payload_offset + actual_mod_size as u64;
        let new_cert_offset = cert_offset + actual_mod_size as u64;

        updated_body[sprdsigned_hdr_offset + 16..sprdsigned_hdr_offset + 24]
            .copy_from_slice(&new_payload_offset.to_le_bytes());
        updated_body[sprdsigned_hdr_offset + 32..sprdsigned_hdr_offset + 40]
            .copy_from_slice(&new_cert_offset.to_le_bytes());
    }

    output.extend_from_slice(&updated_hdr);
    output
        .extend_from_slice(&modified_img[mod_payload_offset..mod_payload_offset + actual_mod_size]);
    output.extend_from_slice(&updated_body);

    fs::write(merged_img_name, output)?;
    Ok(true)
}
