# Parity Contract — spreadtrum_flash (spd_dump) Rust Port

## End state
**A — Replacement:** A standalone Rust binary (`spd_dump`) and library crate in the repository.
The C implementation remains fully verifiable during the port, and all commands/options/protocols
are implemented 1:1 in Rust.

## Unit of Parity
1. **CLI Invocations**: Arguments, options, subcommands, interactive REPL (`FDL2>` prompt).
2. **Offline Tool Mode Commands**:
   - `mergenv-xml-ex xml old_nv new_nv`
   - `mergenv-cfg-ex cfg old_nv new_nv`
   - `dis_avb_ex sml_or_teecfg tos`
   - `-h` / `--help`
3. **Protocol & Binary Formats**:
   - HDLC framing (0x7E, 0x7D escape, transcode / untranscode).
   - CRC16 (CCITT Kermit / spd_crc16 polynomial `0x11021`) and CRC32 / spd_checksum.
   - BSL command framing, requests, response decoding.
   - GPT (EFI PART) header and partition parsing, XML partition list generation.
   - DHTB sys_img_header, sprdsignedimageheader, postrom headers parsing and patching.
   - NVItem binary parsing, XML/CFG parsing and NV merging.
   - Bootloader control (AVB A/B slot) metadata manipulation.
   - CVE-2022-38693 FDL1 payload hijacking generator (9360, 9632 layouts).

## Acceptable Differences
- Exact wording of `--help` layout or minor formatting (command names and options must match 1:1).
- Wall-clock timing (within USB timeout constraints).
- Order of XML attributes if functionally equivalent (though keeping exact `<Partition id="..." size="..."/>` is preferred).

## Unacceptable Differences
- Exit codes and error conditions.
- Binary outputs for all offline tools:
  - `mergenv-xml-ex` output must byte-for-byte match C `mergenv-xml-ex`.
  - `mergenv-cfg-ex` output must byte-for-byte match C `mergenv-cfg-ex`.
  - `dis_avb_ex` and `bsp_cve_2img` outputs must byte-for-byte match C outputs.
- Packet framing bytes over USB / serial:
  - HDLC encoding, CRC16/CRC32 byte order, escaping, command IDs, lengths.
- Partition and GPT calculation math:
  - LBA sector calculation, NAND ID size calculations (`str_to_size`, `str_to_size_ubi`), partition bounds.
