//! HDLC byte framing and transcoding (0x7E / 0x7D escape).

use crate::bsl_cmd::{HDLC_ESCAPE, HDLC_HEADER};

/// Escapes HDLC_HEADER and HDLC_ESCAPE with HDLC_ESCAPE followed by byte ^ 0x20.
/// Appends to `dst`. Returns number of bytes added.
pub fn spd_transcode(dst: &mut Vec<u8>, src: &[u8]) -> usize {
    let start_len = dst.len();
    for &b in src {
        if b == HDLC_HEADER || b == HDLC_ESCAPE {
            dst.push(HDLC_ESCAPE);
            dst.push(b ^ 0x20);
        } else {
            dst.push(b);
        }
    }
    dst.len() - start_len
}

/// Computes how many bytes from `src` can fit into `n` encoded wire bytes.
pub fn spd_transcode_max(src: &[u8], mut n: usize) -> usize {
    let mut i = 0;
    for &b in src {
        let cost = if b == HDLC_HEADER || b == HDLC_ESCAPE {
            2
        } else {
            1
        };
        if n < cost {
            break;
        }
        n -= cost;
        i += 1;
    }
    i
}

/// Unescapes HDLC bytes.
pub fn spd_untranscode(src: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(src.len());
    let mut esc = false;
    for &b in src {
        if esc {
            if b != (HDLC_HEADER ^ 0x20) && b != (HDLC_ESCAPE ^ 0x20) {
                return Err("invalid escape sequence");
            }
            out.push(b ^ 0x20);
            esc = false;
        } else if b == HDLC_ESCAPE {
            esc = true;
        } else {
            out.push(b);
        }
    }
    if esc {
        return Err("truncated escape");
    }
    Ok(out)
}
