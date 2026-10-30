//! DHTB image headers and postrom handling.

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SysImgHeader {
    pub m_magic_num: u32,
    pub m_version: u32,
    pub m_payload_hash: [u8; 32],
    pub reserved1: [u8; 8],
    pub m_img_size: u32,
    pub reserved2: [u8; 24],
    pub m_firmware_size: u32,
    pub m_unknown_size1: u32,
    pub m_postrom_full_size: u32,
    pub m_postrom_offset: u32,
    pub nickname: [u8; 36],
    pub reserved: [u8; 384],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct PostromMainHeader {
    pub m_magic_num: u32,
    pub m_version: u32,
    pub m_payload_hash: [u8; 32],
    pub reserved1: [u8; 8],
    pub m_img_size: u32,
    pub reserved2: [u8; 24],
    pub m_firmware_size: u32,
    pub m_unknown_size1: u32,
    pub reserved: [u8; 428],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct PostromChildHeader {
    pub m_unknown_num: u32,
    pub m_offset: u32,
    pub m_postrom_payload_size: u32,
    pub rotpk_hash: [u8; 32],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SprdSignedImageHeader {
    pub magic: [u8; 8],
    pub header_version_major: u32,
    pub header_version_minor: u32,
    pub payload_size: u64,
    pub payload_offset: u64,
    pub cert_size: u64,
    pub cert_offset: u64,
    pub priv_size: u64,
    pub priv_offset: u64,
    pub cert_dbg_prim_size: u64,
    pub cert_dbg_prim_offset: u64,
    pub cert_dbg_developer_size: u64,
    pub cert_dbg_developer_offset: u64,
}

pub const SIZEOF_SYS_IMG_HEADER: usize = 512;
pub const SIZEOF_SPRDSIGNEDIMAGEHEADER: usize = 80;

/// For any DHTB data block, compute its true footprint including internal SIMGHDR footer + certs.
pub fn dhtb_data_size(base: &[u8], m_img_size: u32, max_rel: usize) -> usize {
    let raw_end = 0x200 + m_img_size as usize;
    if raw_end + SIZEOF_SPRDSIGNEDIMAGEHEADER > max_rel
        || raw_end + SIZEOF_SPRDSIGNEDIMAGEHEADER > base.len()
    {
        return raw_end;
    }

    // Read fields of SprdSignedImageHeader starting at raw_end
    // cert_size at offset 24, cert_offset at 32
    // priv_size at offset 40, priv_offset at 48
    // cert_dbg_developer_size at offset 64, cert_dbg_developer_offset at 72
    let read_u64_le = |off: usize| -> u64 {
        if off + 8 <= base.len() {
            u64::from_le_bytes(base[off..off + 8].try_into().unwrap())
        } else {
            0
        }
    };

    let cert_size = read_u64_le(raw_end + 24);
    let cert_offset = read_u64_le(raw_end + 32);
    let priv_size = read_u64_le(raw_end + 40);
    let priv_offset = read_u64_le(raw_end + 48);
    let dev_size = read_u64_le(raw_end + 64);
    let dev_offset = read_u64_le(raw_end + 72);

    let mut max_end = raw_end + SIZEOF_SPRDSIGNEDIMAGEHEADER;

    let check_seg = |max_end: &mut usize, s: u64, o: u64| {
        if s != 0 && o != 0 {
            let end = o + s;
            if end > *max_end as u64 && end <= max_rel as u64 {
                *max_end = end as usize;
            }
        }
    };

    check_seg(&mut max_end, cert_size, cert_offset);
    check_seg(&mut max_end, priv_size, priv_offset);
    check_seg(&mut max_end, dev_size, dev_offset);

    max_end
}

/// Computes the proper size of a BSP image file and truncates/writes it back.
pub fn bsp_chsize(filename: &str) -> std::io::Result<usize> {
    use std::fs;
    let mut mem = fs::read(filename)?;
    let size = mem.len();
    if size < SIZEOF_SYS_IMG_HEADER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "broken sprd trusted firmware",
        ));
    }

    let m_img_size = u32::from_le_bytes(mem[0x30..0x34].try_into().unwrap());
    let m_postrom_offset = u32::from_le_bytes(mem[0x38..0x3c].try_into().unwrap()) as usize;

    let mut sizewith_postrom = 0;
    if m_postrom_offset != 0 && m_postrom_offset + 0x200 < size {
        let postrom_slice = &mem[m_postrom_offset..];
        let pmagic = u32::from_le_bytes(postrom_slice[0..4].try_into().unwrap());
        let postrom_img_size =
            u32::from_le_bytes(postrom_slice[0x30..0x34].try_into().unwrap()) as usize;
        if (pmagic == 0x42544844 || pmagic == 0x50534844)
            && postrom_img_size != 0
            && (m_postrom_offset + 0x200 + postrom_img_size <= size)
        {
            sizewith_postrom = m_postrom_offset
                + dhtb_data_size(
                    postrom_slice,
                    postrom_img_size as u32,
                    size - m_postrom_offset,
                );
        }
    }

    if m_img_size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "broken sprd trusted firmware",
        ));
    }

    let mut new_size = dhtb_data_size(&mem, m_img_size, size);
    if sizewith_postrom > new_size {
        new_size = sizewith_postrom;
    }

    eprintln!("chsize bsp image: 0x{:x}", new_size);
    mem.truncate(new_size);
    fs::write(filename, &mem)?;
    Ok(new_size)
}
