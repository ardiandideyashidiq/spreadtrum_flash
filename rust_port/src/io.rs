//! BSL packet encoder, decoder, and I/O context.

use crate::bsl_cmd::*;
use crate::crc::{spd_checksum, spd_crc16, CHK_FIXZERO};
use crate::gpt::Partition;
use crate::hdlc::spd_transcode;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct DaInfo {
    pub dw_version: u32,
    pub b_disable_hdlc: u32,
    pub b_is_old_memory: u8,
    pub b_support_raw_data: u8,
    pub dw_flush_size: u32,
    pub dw_storage_type: u32,
}

pub struct SpdIo {
    pub flags: i32,
    pub verbose: i32,
    pub timeout: Duration,
    pub ptable: Vec<Partition>,
    pub nvid_list: Option<[bool; 0x10000]>,
    // Packet buffers
    pub raw_buf: Vec<u8>,
    pub enc_buf: Vec<u8>,
    pub send_buf: Vec<u8>,
    pub untranscode_buf: Vec<u8>,
    pub recv_buf: Vec<u8>,
    pub temp_buf: Vec<u8>,

    pub raw_len: usize,
    pub enc_len: usize,

    // USB endpoints
    pub usb_device: Option<rusb::DeviceHandle<rusb::GlobalContext>>,
    pub endp_in: u8,
    pub endp_out: u8,
    pub endp_in_blk: u16,
    pub endp_out_blk: u16,
}

impl SpdIo {
    pub fn new(flags: i32) -> Self {
        Self {
            flags,
            verbose: 0,
            timeout: Duration::from_millis(1000),
            ptable: Vec::new(),
            nvid_list: None,
            raw_buf: vec![0u8; 0x10000 * 2],
            enc_buf: vec![0u8; 0x10000 * 2],
            send_buf: Vec::new(),
            untranscode_buf: vec![0u8; 0x10000 * 2],
            recv_buf: vec![0u8; 0x10000 * 2],
            temp_buf: vec![0u8; 0x10000 * 2],
            raw_len: 0,
            enc_len: 0,
            usb_device: None,
            endp_in: 0,
            endp_out: 0,
            endp_in_blk: 0,
            endp_out_blk: 0,
        }
    }

    /// Encodes a message matching encode_msg in common.c.
    pub fn encode_msg(&mut self, msg_type: u16, data: &[u8]) {
        let len = data.len();
        if len > 0xffff {
            panic!("message too long");
        }

        if msg_type == BSL_CMD_CHECK_BAUD {
            self.enc_buf.clear();
            self.enc_buf.resize(len, HDLC_HEADER);
            self.enc_len = len;
            self.send_buf = self.enc_buf.clone();
            if self.untranscode_buf.len() > 1 {
                self.untranscode_buf[1] = HDLC_HEADER;
            }
            return;
        }

        let mut p0 = Vec::with_capacity(4 + len + 2);
        p0.extend_from_slice(&msg_type.to_be_bytes());
        p0.extend_from_slice(&(len as u16).to_be_bytes());
        p0.extend_from_slice(data);

        let chk = if (self.flags & FLAGS_CRC16) != 0 {
            spd_crc16(0, &p0)
        } else {
            spd_checksum(0, &p0, CHK_FIXZERO)
        };
        p0.extend_from_slice(&chk.to_be_bytes());

        self.raw_len = p0.len();

        if (self.flags & FLAGS_TRANSCODE) != 0 {
            self.enc_buf.clear();
            self.enc_buf.push(HDLC_HEADER);
            spd_transcode(&mut self.enc_buf, &p0);
            self.enc_buf.push(HDLC_HEADER);
            self.enc_len = self.enc_buf.len();
            self.send_buf = self.enc_buf.clone();
        } else {
            self.untranscode_buf.clear();
            self.untranscode_buf.push(HDLC_HEADER);
            self.untranscode_buf.extend_from_slice(&p0);
            self.untranscode_buf.push(HDLC_HEADER);
            self.enc_len = self.untranscode_buf.len();
            self.send_buf = self.untranscode_buf.clone();
        }
    }

    /// Returns response type and payload from `raw_buf`.
    pub fn recv_type(&self) -> u16 {
        if self.raw_len >= 2 {
            u16::from_be_bytes(self.raw_buf[0..2].try_into().unwrap())
        } else {
            0
        }
    }

    /// Returns response payload length.
    pub fn recv_payload_len(&self) -> usize {
        if self.raw_len >= 4 {
            u16::from_be_bytes(self.raw_buf[2..4].try_into().unwrap()) as usize
        } else {
            0
        }
    }

    /// Returns response payload slice.
    pub fn recv_payload(&self) -> &[u8] {
        let len = self.recv_payload_len();
        if self.raw_len >= 4 + len {
            &self.raw_buf[4..4 + len]
        } else {
            &[]
        }
    }

    /// Sends the encoded packet over USB.
    pub fn send_msg(&mut self) -> Result<usize, String> {
        if self.enc_len == 0 {
            return Err("empty message".to_string());
        }
        if let Some(handle) = &self.usb_device {
            let slice = &self.send_buf[..self.enc_len];
            let sent = handle
                .write_bulk(self.endp_out, slice, self.timeout)
                .map_err(|e| format!("usb_send failed : {:?}", e))?;
            if (self.enc_len as u16).is_multiple_of(self.endp_out_blk) {
                let _ = handle.write_bulk(self.endp_out, &[], self.timeout);
            }
            if sent != self.enc_len {
                return Err(format!("usb_send failed ({} / {})", sent, self.enc_len));
            }
            Ok(sent)
        } else {
            Ok(self.enc_len)
        }
    }

    /// Receives and decodes packet from USB.
    pub fn recv_msg(&mut self) -> Result<bool, String> {
        if let Some(handle) = &self.usb_device {
            let mut buf = [0u8; 4096];
            let len = handle
                .read_bulk(self.endp_in, &mut buf, self.timeout)
                .map_err(|e| format!("usb_recv failed: {:?}", e))?;
            if len == 0 {
                return Ok(false);
            }
            self.recv_buf[..len].copy_from_slice(&buf[..len]);
            self.raw_len = len;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Sends message and verifies response status ACK (0x80).
    pub fn send_and_check(&mut self) -> Result<bool, String> {
        self.send_msg()?;
        if self.recv_msg()? {
            Ok(self.recv_type() == BSL_REP_ACK)
        } else {
            Ok(false)
        }
    }
}
