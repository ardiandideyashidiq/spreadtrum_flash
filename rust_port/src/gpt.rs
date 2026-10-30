//! GPT structures and XML partition parsing / serialization.

pub const SECTOR_SIZE: usize = 512;
pub const MAX_SECTORS: usize = 32;

#[derive(Clone, Debug, Default)]
pub struct Partition {
    pub name: String,
    pub size: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct EfiHeader {
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub reserved: i32,
    pub current_lba: u64,
    pub backup_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub number_of_partition_entries: i32,
    pub size_of_partition_entry: u32,
    pub partition_entry_array_crc32: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct EfiEntry {
    pub partition_type_guid: [u8; 16],
    pub unique_partition_guid: [u8; 16],
    pub starting_lba: u64,
    pub ending_lba: u64,
    pub attributes: i64,
    pub partition_name: [u8; 72], // UTF-16LE
}

pub fn copy_to_wstr(dest: &mut [u16], s: &str) -> bool {
    let mut i = 0;
    for ch in s.encode_utf16() {
        if i >= dest.len() - 1 {
            return true; // overflow
        }
        dest[i] = ch;
        i += 1;
    }
    if i < dest.len() {
        dest[i] = 0;
    }
    false
}

pub fn copy_from_wstr(src: &[u16]) -> String {
    let mut chars = Vec::new();
    for &val in src {
        if val == 0 {
            break;
        }
        chars.push(val);
    }
    String::from_utf16_lossy(&chars)
}

/// Parses GPT from a reader (e.g. pgpt file bytes)
pub fn parse_gpt(buffer_all: &[u8]) -> Option<(Vec<Partition>, usize, u32)> {
    let mut sector_index = 0;
    let mut found = false;
    let mut header_buf = [0u8; 92];

    while sector_index < MAX_SECTORS {
        let offset = sector_index * SECTOR_SIZE;
        if offset + 8 > buffer_all.len() {
            break;
        }
        if &buffer_all[offset..offset + 8] == b"EFI PART" {
            let hdr_size = std::mem::size_of::<EfiHeader>();
            if offset + hdr_size <= buffer_all.len() {
                header_buf.copy_from_slice(&buffer_all[offset..offset + hdr_size]);
                found = true;
                break;
            }
        }
        sector_index += 1;
    }

    if !found {
        return None;
    }

    let storage_type = if sector_index == 1 { 0x102 } else { 0x103 };
    let real_sector_size = SECTOR_SIZE * sector_index;

    let partition_entry_lba = u64::from_le_bytes(header_buf[72..80].try_into().unwrap());
    let number_of_partition_entries =
        i32::from_le_bytes(header_buf[80..84].try_into().unwrap()) as usize;
    let size_of_entry = u32::from_le_bytes(header_buf[84..88].try_into().unwrap()) as usize;

    let entries_offset = (partition_entry_lba as usize) * real_sector_size;
    let mut partitions = Vec::new();

    for i in 0..number_of_partition_entries {
        let entry_off = entries_offset + i * size_of_entry;
        if entry_off + 128 > buffer_all.len() {
            break;
        }
        let starting_lba = u64::from_le_bytes(
            buffer_all[entry_off + 32..entry_off + 40]
                .try_into()
                .unwrap(),
        );
        let ending_lba = u64::from_le_bytes(
            buffer_all[entry_off + 40..entry_off + 48]
                .try_into()
                .unwrap(),
        );
        if starting_lba == 0 && ending_lba == 0 {
            break;
        }

        let name_bytes = &buffer_all[entry_off + 56..entry_off + 128];
        let mut u16_words = [0u16; 36];
        for j in 0..36 {
            u16_words[j] = u16::from_le_bytes(name_bytes[j * 2..j * 2 + 2].try_into().unwrap());
        }
        let name = copy_from_wstr(&u16_words);
        let lba_count = ending_lba - starting_lba + 1;
        let size = lba_count * (real_sector_size as u64);

        partitions.push(Partition { name, size });
    }

    Some((partitions, real_sector_size, storage_type))
}

/// Generates partition list XML matching C gpt_info() output.
pub fn generate_partition_xml(ptable: &[Partition]) -> String {
    let mut out = String::from("<Partitions>\n");
    let n = ptable.len();
    for (i, p) in ptable.iter().enumerate() {
        if i + 1 == n {
            out.push_str(&format!(
                "    <Partition id=\"{}\" size=\"0x{:x}\"/>\n",
                p.name, !0u32
            ));
        } else {
            out.push_str(&format!(
                "    <Partition id=\"{}\" size=\"{}\"/>\n",
                p.name,
                p.size >> 20
            ));
        }
    }
    out.push_str("</Partitions>");
    out
}

/// Parses partition list XML matching scan_xml_partitions in common.c.
pub fn scan_xml_partitions(xml_content: &str) -> Result<Vec<Partition>, &'static str> {
    let mut partitions = Vec::new();
    let mut in_partitions = false;

    // Use token-based or regex/simple scanner matching C scan_xml_partitions
    let bytes = xml_content.as_bytes();
    let mut p = 0;
    let len = bytes.len();

    while p < len {
        let b = bytes[p];
        p += 1;
        if b.is_ascii_whitespace() {
            continue;
        }
        if b != b'<' {
            if !in_partitions {
                continue;
            }
            return Err("xml: unexpected symbol");
        }

        // Check comment <!--
        if p + 3 <= len && &bytes[p..p + 3] == b"!--" {
            p += 3;
            // find --
            if let Some(pos) = xml_content[p..].find("--") {
                p += pos + 2;
                if p < len && bytes[p] == b'>' {
                    p += 1;
                    continue;
                }
            }
            return Err("xml: unexpected comment syntax");
        }

        if !in_partitions {
            if p + 11 <= len && &bytes[p..p + 11] == b"Partitions>" {
                p += 11;
                in_partitions = true;
                continue;
            }
            // Skip tag
            if let Some(pos) = bytes[p..].iter().position(|&c| c == b'>') {
                p += pos + 1;
                continue;
            }
            return Err("xml: unexpected syntax");
        }

        // Inside Partitions:
        if p + 12 <= len && &bytes[p..p + 12] == b"/Partitions>" {
            break;
        }

        // Expect Partition id="..." size="..."
        let rest = &xml_content[p..];
        if rest.starts_with("Partition ") {
            let tag_end = rest.find('>').ok_or("xml: unclosed Partition tag")?;
            let tag_content = &rest[..tag_end];
            p += tag_end + 1;

            // Extract id="..."
            let id_start = tag_content.find("id=\"").ok_or("missing id")? + 4;
            let id_end = tag_content[id_start..]
                .find('"')
                .ok_or("unclosed id quote")?
                + id_start;
            let id = &tag_content[id_start..id_end];

            // Extract size="..."
            let size_start = tag_content.find("size=\"").ok_or("missing size")? + 6;
            let size_end = tag_content[size_start..]
                .find('"')
                .ok_or("unclosed size quote")?
                + size_start;
            let size_str = &tag_content[size_start..size_end];

            let size: i64 = if size_str.starts_with("0x") || size_str.starts_with("0X") {
                i64::from_str_radix(&size_str[2..], 16).unwrap_or(0)
            } else {
                size_str.parse().unwrap_or(0)
            };

            partitions.push(Partition {
                name: id.to_string(),
                size: (size as u64) << 20,
            });
        } else {
            return Err("xml: unexpected tag in Partitions");
        }
    }

    Ok(partitions)
}
