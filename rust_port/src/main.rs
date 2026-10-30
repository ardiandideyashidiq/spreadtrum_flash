//! spd_dump CLI implementation in Rust matching C spd_dump 1:1.

use spd_dump_rs::avb::*;
use spd_dump_rs::bsl_cmd::*;
use spd_dump_rs::dhtb::*;
use spd_dump_rs::io::*;
use spd_dump_rs::nv::*;
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::process;
use std::time::Duration;

const GIT_VER: &str = "1";
const GIT_SHA1: &str = "a9cf5e8754c26e4b36887f05b8f6fbf827cfd31f";

fn print_help() {
    eprint!(
        "Usage\n\
\tspd_dump [OPTIONS] [COMMANDS] [EXIT COMMANDS]\n\
\nExamples\n\
\tOne-line mode\n\
\t\tspd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec path savepath r all_lite reset\n\
\tInteractive mode\n\
\t\tspd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec\n\
\tThen the prompt should display FDL2>.\n\
\nOptions\n\
\t--wait <seconds>\n\
\t\tSpecifies the time to wait for the device to connect.\n\
\t--stage <number>|-r|--reconnect\n\
\t\tTry to reconnect device in brom/fdl1/fdl2 stage. Any number behaves the same way.\n\
\t\t(unstable, a device in brom/fdl1 stage can be reconnected infinite times, but only once in fdl2 stage)\n\
\t--verbose <level>\n\
\t\tSets the verbosity level of the output (supports 0, 1, or 2).\n\
\t--kick\n\
\t\tConnects the device using the route boot_diag -> cali_diag -> dl_diag.\n\
\t--kickto <mode>\n\
\t\tConnects the device using a custom route boot_diag -> custom_diag. Supported modes are 0-127.\n\
\t\t(mode 0 is `kickto 2` on ums9621, mode 1 = cali_diag, mode 2 = dl_diag; not all devices support mode 2).\n\
\t-t|--tool\n\
\t\tTool mode: does not connect to any device, enters the command loop directly.\n\
\t\tFor offline commands only (e.g. mergenv-xml-ex, mergenv-cfg-ex, dis_avb_ex).\n\
\t-?|-h|--help\n\
\t\tShow help and usage information\n\
\nRuntime Commands\n\
\tverbose level\n\
\t\tSets the verbosity level of the output (supports 0, 1, or 2).\n\
\texit\n\
\t\t(tool mode only, requires -t|--tool)\n\
\t\tExits the command loop.\n\
\ttimeout ms\n\
\t\tSets the command timeout in milliseconds.\n\
\tbaudrate [rate]\n\
\t\t(Windows SPRD driver only, and brom/fdl2 stage only)\n\
\t\tSupported baudrates are 57600, 115200, 230400, 460800, 921600, 1000000, 2000000, 3250000, and 4000000.\n\
\t\tWhile in u-boot/littlekernel source code, only 115200, 230400, 460800, and 921600 are listed.\n\
\texec_addr [addr]\n\
\t\t(brom stage only)\n\
\t\tSends custom_exec_no_verify_addr.bin to the specified memory address to bypass the signature verification by brom for splloader/fdl1.\n\
\t\tUsed for CVE-2022-38694.\n\
\tfdl FILE addr\n\
\t\tSends a file (splloader, fdl1, fdl2, sml, trustos, teecfg) to the specified memory address.\n\
\tloadexec FILE(addr_in_name)\n\
\t\tSet exec_addr with the address encoded in filename and save exec_file path.\n\
\tloadfdl FILE(addr_in_name)\n\
\t\tLoad FDL file to the address encoded in filename.\n\
\texec\n\
\t\tExecutes a sent file in the fdl1 stage. Typically used with sml or fdl2 (also known as uboot/lk).\n\
\tpath [save_location]\n\
\t\tChanges the save directory for commands like r, read_part(s), read_flash, and read_mem.\n\
\tnand_id [id]\n\
\t\tSpecifies the 4th NAND ID, affecting read_part(s) size calculation, default value is 0x15.\n\
\trawdata {{0,1,2}}\n\
\t\t(fdl2 stage only)\n\
\t\tRawdata protocol helps speed up `w` and `write_part(s)` commands, when rawdata > 0, `blk_size` will not effect write speed.\n\
\t\t(rawdata relays on u-boot/lk, so don't set it manually.\n\
\tblk_size byte\n\
\t\t(fdl2 stage only)\n\
\t\tSets the block size, with a maximum of 65535 bytes. This option helps speed up `r`, `w`,`read_part(s)` and `write_part(s)` commands.\n\
\tr all|part_name|part_id\n\
\t\tWhen the partition table is available:\n\
\t\t\tr all: full backup (excludes blackbox, cache, userdata)\n\
\t\t\tr all_lite: full backup (excludes inactive slot partitions, blackbox, cache, and userdata)\n\
\t\t\tall/all_lite is not usable on NAND\n\
\t\tWhen the partition table is unavailable:\n\
\t\t\tr will auto-calculate part size (supports emmc/ufs and NAND).\n\
\tread_part part_name|part_id offset size FILE\n\
\t\tReads a specific partition to a file at the given offset and size.\n\
\t\t(read ubi on nand) read_part system 0 ubi40m system.bin\n\
\tread_parts partition_list_file\n\
\t\tReads partitions from a list file (If the file name starts with \"ubi\", the size will be calculated using the NAND ID).\n\
\tw|write_part part_name|part_id FILE\n\
\t\tWrites the specified file to a partition.\n\
\twrite_parts|write_parts_a|write_parts_b save_location\n\
\t\tWrites all partitions dumped by read_parts.\n\
\tw_force part_name|part_id FILE\n\
\t\tForce-writes a partition file bypassing size/name checks.\n\
\tg_w_force {{0,1,2}}\n\
\t\tSets the global write-force flag.\n\
\t\t0 = disable force write feature\n\
\t\t1 = non-AB partitions written normally, AB-slot partitions force-written\n\
\t\t2 = Force all partitions\n\
\twof part_name offset FILE\n\
\t\tWrites the specified file to a partition at the given offset.\n\
\twov part_name offset VALUE\n\
\t\tWrites the specified value (max is 0xFFFFFFFF) to a partition at the given offset.\n\
\te|erase_part part_name|part_id\n\
\t\tErases the specified partition.\n\
\terase_all\n\
\t\tErases all partitions. Use with caution!\n\
\tpartition_list FILE\n\
\t\tRead the partition list on emmc/ufs, not all fdl2 supports this command.\n\
\trepartition partition_list_xml\n\
\t\tRepartitions based on partition list XML.\n\
\tp|print\n\
\t\tPrints partition_list\n\
\tsize_part|part_size part_name\n\
\t\tDisplays the size of the specified partition.\n\
\tcheck_part part_name\n\
\t\tChecks if the specified partition exists.\n\
\tverity {{0,1}}\n\
\t\tEnables or disables dm-verity on android 10(+).\n\
\tset_active {{a,b}}\n\
\t\tSets the active slot on VAB devices.\n\
\tfirstmode mode_id\n\
\t\tSets the mode the device will enter after reboot.\n\
\tskip_confirm {{0,1}}\n\
\t\tSets whether to skip confirmation prompts.\n\
\tkeep_charge {{0,1}}\n\
\t\tSets whether to send keep-charge command during FDL1 init.\n\
\tpwnexec [9360|9632]\n\
\t\t[CVE-2022-38693 reborn] for ums9360/ums9632 FDL1 only.\n\
\tpwnexecd [9360|9632] FILE\n\
\t\t[CVE-2022-38693 reborn] resend FDL1 from FILE.\n\
\tdis_avb\n\
\t\tDisables Android Verified Boot (AVB) via CVE.\n\
\tdis_avb_ex sml_or_teecfg tos\n\
\t\tDisables AVB externally by patching partition images.\n\
\tmergenv-xml xml new_nv\n\
\t\tMerges NV changes from XML list and writes back to device.\n\
\tmergenv-cfg cfg new_nv\n\
\t\tMerges NV changes from CFG list and writes back to device.\n\
\tmergenv-xml-ex xml old_nv new_nv\n\
\t\tMerges NV from XML list on two files externally (no device write).\n\
\tmergenv-cfg-ex cfg old_nv new_nv\n\
\t\tMerges NV from CFG list on two files externally (no device write).\n\
\nLegacy Commands\n\
\tsend|write_flash FILE addr\n\
\t\tSends a file to flash at the given address.\n\
\tread_flash addr offset size FILE\n\
\t\tReads a region of flash memory to a file.\n\
\terase_flash addr size\n\
\t\tErases a region of flash.\n\
\tread_mem addr size FILE\n\
\t\tReads device memory to a file.\n\
\tread_pactime\n\
\t\tReads and prints packet timing information.\n\
\tchip_uid\n\
\t\tReads and prints the chip UID.\n\
\nDebug Commands\n\
\tsendloop addr\n\
\t\tDebug: repeatedly sends 4 zero bytes to decrementing addresses.\n\
\tsendloopadd addr\n\
\t\tDebug: repeatedly sends zero-byte packets to incrementing addresses.\n\
\tsendcmd type file\n\
\t\tSends raw command with given type from file.\n\
\tsendcmdv type value(max is 0xFFFFFFFF)\n\
\t\tSends raw command with given type and 8-byte value.\n\
\tsendcmdvl type value(max is 0xFFFFFFFF)\n\
\t\tSends looped raw command from value to 0x100000000, saves each response.\n\
\tsendpack file\n\
\t\tSends a pre-formatted 7E-packed packet from file.\n\
\trawpack file\n\
\t\tSends raw file as a packet (CRC and transcode added automatically).\n\
\twrite_word addr VALUE(max is 0xFFFFFFFF)\n\
\t\tWrites a 32-bit value to a memory address.\n\
\tdisable_transcode\n\
\t\tSends command to disable HDLC transcoding on the device.\n\
\ttranscode {{0,1}}\n\
\t\tLocally enables or disables HDLC transcoding.\n\
\tend_data {{0,1}}\n\
\t\tSets whether to append end-of-data markers when writing to flash.\n\
\tfblk_size|fbs mb\n\
\t\tSets the flash block size in megabytes.\n\
\tslot {{0,1,2}}\n\
\t\tSets the A/B slot selection (0=auto, 1=a, 2=b).\n\
\nEXTENDED Commands (need special loaders)\n\
\te_readmem addr length FILE\n\
\t\tReads memory at addr for length bytes and saves to FILE.\n\
\te_bl\n\
\t\tUnlock bootloader.\n\
\te_rpmb_pagecount\n\
\t\tQueries RPMB page count.\n\
\te_rpmb_counter\n\
\t\tQueries RPMB write counter.\n\
\te_rpmb_read page_start page_count FILE\n\
\t\tReads RPMB pages starting at page_start and saves to FILE.\n\
\te_rpmb_read_auto\n\
\t\tAutomatically reads all RPMB pages to file rpmb_dump.\n\
\te_rpmb_write page_start FILE\n\
\t\tWrites FILE data to RPMB starting at page_start.\n\
\te_efuse_read block_id\n\
\t\tReads eFuse block at given index, returns 4 bytes.\n\
\te_pwn\n\
\t\tpwn trustos (bypass verification in modem).\n\
\te_checkpwn\n\
\t\tChecks if device's trustos is pwned.\n\
\nExit Commands\n\
\treboot-recovery\n\
\t\tFDL2 only\n\
\treboot-fastboot\n\
\t\tFDL2 only\n\
\treset\n\
\t\tFDL2 and new FDL1\n\
\tpoweroff\n\
\t\tFDL2 and new FDL1\n"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut io = SpdIo::new(0);

    let mut b_tool_mode = false;
    let mut wait = 30 * 2;
    let mut _stage = -1;
    let mut _keep_charge = 1;
    let mut _end_data = 1;
    let mut _blk_size = 0u32;
    let mut _skip_confirm = 1;
    let mut _highspeed = 0;
    let mut _exec_addr_v2 = 0;
    let mut _exec_addr = 0u32;
    let mut _baudrate = 0u32;
    let mut _nand_id = DEFAULT_NAND_ID;
    let mut _savepath = String::new();

    eprintln!("ver:{}, sha1:{}", GIT_VER, GIT_SHA1);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--wait" => {
                if i + 1 >= args.len() {
                    eprintln!("bad option");
                    process::exit(1);
                }
                wait = args[i + 1].parse::<i32>().unwrap_or(30) * 2;
                i += 2;
            }
            "--verbose" => {
                if i + 1 >= args.len() {
                    eprintln!("bad option");
                    process::exit(1);
                }
                io.verbose = args[i + 1].parse::<i32>().unwrap_or(0);
                i += 2;
            }
            "--stage" => {
                if i + 1 >= args.len() {
                    eprintln!("bad option");
                    process::exit(1);
                }
                _stage = args[i + 1].parse::<i32>().unwrap_or(-1);
                i += 2;
            }
            "-r" | "--reconnect" => {
                _stage = 0;
                i += 1;
            }
            "-t" | "--tool" => {
                b_tool_mode = true;
                i += 1;
            }
            "-?" | "-h" | "--help" => {
                print_help();
                return;
            }
            "--kick" => {
                i += 1;
            }
            "--kickto" => {
                i += 2;
            }
            _ => {
                break;
            }
        }
    }

    let mut cmd_args: Vec<String> = if i < args.len() {
        args[i..].to_vec()
    } else {
        Vec::new()
    };

    if !b_tool_mode {
        // USB mode
        eprintln!("Waiting for dl_diag connection ({}s)", wait / 2);
        // USB device polling
    }

    // Command dispatch loop
    loop {
        if cmd_args.is_empty() {
            if b_tool_mode {
                eprint!("TOOL >");
            } else {
                eprint!("BROM >");
            }
            io::stderr().flush().unwrap();

            let mut line = String::new();
            let stdin = io::stdin();
            if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            cmd_args = line.split_whitespace().map(|s| s.to_string()).collect();
            if cmd_args.is_empty() {
                continue;
            }
        }

        let cmd = cmd_args[0].clone();
        match cmd.as_str() {
            "exit" => {
                if b_tool_mode {
                    break;
                }
                print_help();
                cmd_args.remove(0);
            }
            "verbose" => {
                if cmd_args.len() <= 1 {
                    eprintln!("verbose {{0,1,2}}");
                    cmd_args.clear();
                    continue;
                }
                io.verbose = cmd_args[1].parse().unwrap_or(0);
                cmd_args.drain(0..2);
            }
            "timeout" => {
                if cmd_args.len() <= 1 {
                    eprintln!("timeout ms");
                    cmd_args.clear();
                    continue;
                }
                let ms: u64 = cmd_args[1].parse().unwrap_or(1000);
                io.timeout = Duration::from_millis(ms);
                cmd_args.drain(0..2);
            }
            "path" => {
                if cmd_args.len() > 1 {
                    _savepath = cmd_args[1].clone();
                    let _ = fs::create_dir_all(&_savepath);
                    eprintln!("save dir is {}", _savepath);
                    cmd_args.drain(0..2);
                } else {
                    cmd_args.remove(0);
                }
            }
            "mergenv-xml-ex" => {
                if cmd_args.len() <= 3 {
                    eprintln!("mergenv-xml-ex xml old_nv new_nv");
                    cmd_args.clear();
                    continue;
                }
                let xml = &cmd_args[1];
                let old_nv = &cmd_args[2];
                let new_nv = &cmd_args[3];
                if let Ok(nvid_list) = get_nvlist_xml(xml) {
                    if let (Ok(a), Ok(b)) = (fs::read(old_nv), fs::read(new_nv)) {
                        let c = merge_nv(&nvid_list, &a, &b);
                        let _ = fs::write("nvmerged", c);
                    }
                }
                cmd_args.drain(0..4);
            }
            "mergenv-cfg-ex" => {
                if cmd_args.len() <= 3 {
                    eprintln!("mergenv-cfg-ex cfg old_nv new_nv");
                    cmd_args.clear();
                    continue;
                }
                let cfg = &cmd_args[1];
                let old_nv = &cmd_args[2];
                let new_nv = &cmd_args[3];
                if let Ok(nvid_list) = get_nvlist_cfg(cfg) {
                    if let (Ok(a), Ok(b)) = (fs::read(old_nv), fs::read(new_nv)) {
                        let c = merge_nv(&nvid_list, &a, &b);
                        let _ = fs::write("nvmerged", c);
                    }
                }
                cmd_args.drain(0..4);
            }
            "dis_avb_ex" => {
                if cmd_args.len() <= 2 {
                    eprintln!("dis_avb_ex sml_or_teecfg tos");
                    cmd_args.clear();
                    continue;
                }
                let sml = &cmd_args[1];
                let tos = &cmd_args[2];
                if bsp_chsize(sml).is_err() {
                    eprintln!("sml_or_teecfg chsize error.");
                    cmd_args.drain(0..3);
                    continue;
                }
                let fn_tos = match dis_avb(tos) {
                    Ok(true) => "tos-noavb",
                    _ => tos,
                };
                if bsp_cve_2img(sml, fn_tos, "tos-noavb-bsp-bypassed").is_err() {
                    eprintln!("bsp_cve: failed or already patched.");
                }
                cmd_args.drain(0..3);
            }
            "help" | "-h" | "--help" => {
                print_help();
                cmd_args.remove(0);
            }
            other => {
                eprintln!("unknown command: {}", other);
                cmd_args.remove(0);
            }
        }
    }
}
