//! NV parsing, XML / CFG NV list extraction, and NV merging.

use std::fs;
use std::io::{self, BufRead};

#[derive(Clone, Copy, Default, Debug)]
pub struct NvEntry {
    pub length: u16,
    pub offset: usize,
    pub saved: bool,
}

/// Parses NV IDs from XML file matching get_nvlist_xml in common.c.
pub fn get_nvlist_xml(fn_path: &str) -> io::Result<[bool; 0x10000]> {
    let mut nvid_list = [false; 0x10000];
    let content = fs::read_to_string(fn_path)?;

    // Scan for <NVItem> ... <ID> ... </ID>
    let mut pos = 0;
    while let Some(nvitem_pos) = content[pos..].find("<NVItem>") {
        let block_start = pos + nvitem_pos;
        let block_end = match content[block_start..].find("</NVItem>") {
            Some(e) => block_start + e + 9,
            None => content.len(),
        };
        let block = &content[block_start..block_end];
        if let Some(id_start_rel) = block.find("<ID>") {
            let id_val_start = id_start_rel + 4;
            if let Some(id_end_rel) = block[id_val_start..].find("</ID>") {
                let id_str = block[id_val_start..id_val_start + id_end_rel].trim();
                let id = if id_str.starts_with("0x") || id_str.starts_with("0X") {
                    usize::from_str_radix(&id_str[2..], 16).unwrap_or(0)
                } else {
                    id_str.parse::<usize>().unwrap_or(0)
                };
                if id < 0x10000 {
                    nvid_list[id] = true;
                }
            }
        }
        pos = block_end;
    }

    // Default IDs always included in common.c
    nvid_list[5] = true;
    nvid_list[0x179] = true;
    nvid_list[0x186] = true;
    nvid_list[0x1e4] = true;
    nvid_list[2] = true;
    nvid_list[0x516] = true;
    nvid_list[0x12d] = true;
    nvid_list[0x9c4] = true;

    Ok(nvid_list)
}

/// Parses NV IDs from CFG file matching get_nvlist_cfg in common.c.
pub fn get_nvlist_cfg(fn_path: &str) -> io::Result<[bool; 0x10000]> {
    let mut nvid_list = [false; 0x10000];
    let file = fs::File::open(fn_path)?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            let hex_str = parts[1].trim_start_matches("0x").trim_start_matches("0X");
            if let Ok(id) = usize::from_str_radix(hex_str, 16) {
                if id < 0x10000 {
                    nvid_list[id] = true;
                }
            }
        }
    }

    nvid_list[5] = true;
    nvid_list[0x179] = true;
    nvid_list[0x186] = true;
    nvid_list[0x1e4] = true;
    nvid_list[2] = true;
    nvid_list[0x516] = true;
    nvid_list[0x12d] = true;
    nvid_list[0x9c4] = true;

    Ok(nvid_list)
}

/// Merges NV items from source A and B based on nvid_list, producing output C.
/// Exactly matches merge_nv() in common.c.
pub fn merge_nv(nvid_list: &[bool; 0x10000], a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut nvid_list_offset = vec![NvEntry::default(); 0x10000];
    let a_size = a.len();
    let b_size = b.len();

    let mut pos = 4;
    if a.len() >= 4 && u32::from_le_bytes(a[0..4].try_into().unwrap()) == 0x4e56 {
        pos += 0x200;
    }

    while pos + 4 <= a_size {
        let item_type = u16::from_le_bytes(a[pos..pos + 2].try_into().unwrap()) as usize;
        let length = u16::from_le_bytes(a[pos + 2..pos + 4].try_into().unwrap());
        if length == 0 || pos + 4 + (length as usize) > a_size {
            break;
        }
        pos += 4;
        nvid_list_offset[item_type].length = length;
        nvid_list_offset[item_type].offset = pos;
        pos += length as usize;

        pos = (pos + 3) & !3;
        if pos + 2 <= a_size && u16::from_le_bytes(a[pos..pos + 2].try_into().unwrap()) == 0xffff {
            break;
        }
    }

    let mut c = Vec::with_capacity(a_size + b_size + 8);
    pos = 4;
    if b.len() >= 4 && u32::from_le_bytes(b[0..4].try_into().unwrap()) == 0x4e56 {
        pos += 0x200;
    }

    // copy 4 header bytes from b
    c.extend_from_slice(&b[pos - 4..pos]);

    while pos + 4 <= b_size {
        let item_type = u16::from_le_bytes(b[pos..pos + 2].try_into().unwrap()) as usize;
        let length = u16::from_le_bytes(b[pos + 2..pos + 4].try_into().unwrap());
        if pos + 4 + (length as usize) > b_size {
            break;
        }
        pos += 4;
        if nvid_list[item_type] && nvid_list_offset[item_type].length != 0 {
            c.extend_from_slice(&(item_type as u16).to_le_bytes());
            c.extend_from_slice(&nvid_list_offset[item_type].length.to_le_bytes());
            let off = nvid_list_offset[item_type].offset;
            let len = nvid_list_offset[item_type].length as usize;
            c.extend_from_slice(&a[off..off + len]);
        } else {
            c.extend_from_slice(&b[pos - 4..pos + (length as usize)]);
        }
        nvid_list_offset[item_type].saved = true;
        pos += length as usize;
        pos = (pos + 3) & !3;

        let aligned_c = (c.len() + 3) & !3;
        c.resize(aligned_c, 0);

        if pos + 2 <= b_size && u16::from_le_bytes(b[pos..pos + 2].try_into().unwrap()) == 0xffff {
            break;
        }
    }

    // Append items from A that were not in B
    for (i, entry) in nvid_list_offset.iter().enumerate() {
        if entry.length != 0 && !entry.saved {
            c.extend_from_slice(&(i as u16).to_le_bytes());
            c.extend_from_slice(&entry.length.to_le_bytes());
            let off = entry.offset;
            let len = entry.length as usize;
            c.extend_from_slice(&a[off..off + len]);
            let aligned_c = (c.len() + 3) & !3;
            c.resize(aligned_c, 0);
        }
    }

    let endbuf = [0xffu8; 8];
    c.extend_from_slice(&endbuf);
    c
}
