//! Software AES-128 ECB encryption matching common.c.

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[inline]
fn aes_xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

#[inline]
fn aes_mixcol32(c: u32) -> u32 {
    let b0 = c as u8;
    let b1 = (c >> 8) as u8;
    let b2 = (c >> 16) as u8;
    let b3 = (c >> 24) as u8;
    let d0 = aes_xtime(b0) ^ aes_xtime(b1) ^ b1 ^ b2 ^ b3;
    let d1 = b0 ^ aes_xtime(b1) ^ aes_xtime(b2) ^ b2 ^ b3;
    let d2 = b0 ^ b1 ^ aes_xtime(b2) ^ aes_xtime(b3) ^ b3;
    let d3 = aes_xtime(b0) ^ b0 ^ b1 ^ b2 ^ aes_xtime(b3);
    (d0 as u32) | ((d1 as u32) << 8) | ((d2 as u32) << 16) | ((d3 as u32) << 24)
}

fn aes128_keyexpand(key: &[u8; 16], rk: &mut [u32; 44]) {
    const RCON: [u8; 11] = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    ];
    for i in 0..4 {
        rk[i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 4..44 {
        let mut tmp = rk[i - 1];
        if (i & 3) == 0 {
            tmp = tmp.rotate_right(8);
            tmp = (AES_SBOX[(tmp & 0xff) as usize] as u32)
                | ((AES_SBOX[((tmp >> 8) & 0xff) as usize] as u32) << 8)
                | ((AES_SBOX[((tmp >> 16) & 0xff) as usize] as u32) << 16)
                | ((AES_SBOX[((tmp >> 24) & 0xff) as usize] as u32) << 24);
            tmp ^= RCON[i >> 2] as u32;
        }
        rk[i] = rk[i - 4] ^ tmp;
    }
}

fn aes128_encrypt_block(rk: &[u32; 44], input: &[u8; 16], out: &mut [u8; 16]) {
    let mut s0 = u32::from_le_bytes(input[0..4].try_into().unwrap()) ^ rk[0];
    let mut s1 = u32::from_le_bytes(input[4..8].try_into().unwrap()) ^ rk[1];
    let mut s2 = u32::from_le_bytes(input[8..12].try_into().unwrap()) ^ rk[2];
    let mut s3 = u32::from_le_bytes(input[12..16].try_into().unwrap()) ^ rk[3];

    for r in 1..=9 {
        let a = [
            s0 as u8,
            (s0 >> 8) as u8,
            (s0 >> 16) as u8,
            (s0 >> 24) as u8,
            s1 as u8,
            (s1 >> 8) as u8,
            (s1 >> 16) as u8,
            (s1 >> 24) as u8,
            s2 as u8,
            (s2 >> 8) as u8,
            (s2 >> 16) as u8,
            (s2 >> 24) as u8,
            s3 as u8,
            (s3 >> 8) as u8,
            (s3 >> 16) as u8,
            (s3 >> 24) as u8,
        ];
        let t0 = (AES_SBOX[a[0] as usize] as u32)
            | ((AES_SBOX[a[5] as usize] as u32) << 8)
            | ((AES_SBOX[a[10] as usize] as u32) << 16)
            | ((AES_SBOX[a[15] as usize] as u32) << 24);
        let t1 = (AES_SBOX[a[4] as usize] as u32)
            | ((AES_SBOX[a[9] as usize] as u32) << 8)
            | ((AES_SBOX[a[14] as usize] as u32) << 16)
            | ((AES_SBOX[a[3] as usize] as u32) << 24);
        let t2 = (AES_SBOX[a[8] as usize] as u32)
            | ((AES_SBOX[a[13] as usize] as u32) << 8)
            | ((AES_SBOX[a[2] as usize] as u32) << 16)
            | ((AES_SBOX[a[7] as usize] as u32) << 24);
        let t3 = (AES_SBOX[a[12] as usize] as u32)
            | ((AES_SBOX[a[1] as usize] as u32) << 8)
            | ((AES_SBOX[a[6] as usize] as u32) << 16)
            | ((AES_SBOX[a[11] as usize] as u32) << 24);

        s0 = aes_mixcol32(t0) ^ rk[r * 4];
        s1 = aes_mixcol32(t1) ^ rk[r * 4 + 1];
        s2 = aes_mixcol32(t2) ^ rk[r * 4 + 2];
        s3 = aes_mixcol32(t3) ^ rk[r * 4 + 3];
    }

    let a = [
        s0 as u8,
        (s0 >> 8) as u8,
        (s0 >> 16) as u8,
        (s0 >> 24) as u8,
        s1 as u8,
        (s1 >> 8) as u8,
        (s1 >> 16) as u8,
        (s1 >> 24) as u8,
        s2 as u8,
        (s2 >> 8) as u8,
        (s2 >> 16) as u8,
        (s2 >> 24) as u8,
        s3 as u8,
        (s3 >> 8) as u8,
        (s3 >> 16) as u8,
        (s3 >> 24) as u8,
    ];
    s0 = (AES_SBOX[a[0] as usize] as u32)
        | ((AES_SBOX[a[5] as usize] as u32) << 8)
        | ((AES_SBOX[a[10] as usize] as u32) << 16)
        | ((AES_SBOX[a[15] as usize] as u32) << 24) ^ rk[40];
    s1 = (AES_SBOX[a[4] as usize] as u32)
        | ((AES_SBOX[a[9] as usize] as u32) << 8)
        | ((AES_SBOX[a[14] as usize] as u32) << 16)
        | ((AES_SBOX[a[3] as usize] as u32) << 24) ^ rk[41];
    s2 = (AES_SBOX[a[8] as usize] as u32)
        | ((AES_SBOX[a[13] as usize] as u32) << 8)
        | ((AES_SBOX[a[2] as usize] as u32) << 16)
        | ((AES_SBOX[a[7] as usize] as u32) << 24) ^ rk[42];
    s3 = (AES_SBOX[a[12] as usize] as u32)
        | ((AES_SBOX[a[1] as usize] as u32) << 8)
        | ((AES_SBOX[a[6] as usize] as u32) << 16)
        | ((AES_SBOX[a[11] as usize] as u32) << 24) ^ rk[43];

    out[0..4].copy_from_slice(&s0.to_le_bytes());
    out[4..8].copy_from_slice(&s1.to_le_bytes());
    out[8..12].copy_from_slice(&s2.to_le_bytes());
    out[12..16].copy_from_slice(&s3.to_le_bytes());
}

pub fn aes128_ecb_encrypt(key: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    let mut rk = [0u32; 44];
    aes128_keyexpand(key, &mut rk);
    let mut ct = vec![0u8; pt.len()];
    for (chunk_in, chunk_out) in pt.chunks_exact(16).zip(ct.chunks_exact_mut(16)) {
        let in_block: &[u8; 16] = chunk_in.try_into().unwrap();
        let out_block: &mut [u8; 16] = chunk_out.try_into().unwrap();
        aes128_encrypt_block(&rk, in_block, out_block);
    }
    ct
}
