//! BSL commands, reply constants, and framing constants.

pub const HDLC_HEADER: u8 = 0x7e;
pub const HDLC_ESCAPE: u8 = 0x7d;
pub const DEFAULT_NAND_ID: i32 = 0x15;
pub const DEFAULT_BLK_SIZE: u32 = 0x1000;

pub const FLAGS_CRC16: i32 = 1;
pub const FLAGS_TRANSCODE: i32 = 2;

// Commands
pub const BSL_CMD_CONNECT: u16 = 0x00;
pub const BSL_CMD_START_DATA: u16 = 0x01;
pub const BSL_CMD_MIDST_DATA: u16 = 0x02;
pub const BSL_CMD_END_DATA: u16 = 0x03;
pub const BSL_CMD_EXEC_DATA: u16 = 0x04;
pub const BSL_CMD_NORMAL_RESET: u16 = 0x05;
pub const BSL_CMD_READ_FLASH: u16 = 0x06;
pub const BSL_CMD_READ_CHIP_TYPE: u16 = 0x07;
pub const BSL_CMD_READ_NVITEM: u16 = 0x08;
pub const BSL_CMD_CHANGE_BAUD: u16 = 0x09;
pub const BSL_CMD_ERASE_FLASH: u16 = 0x0A;
pub const BSL_CMD_REPARTITION: u16 = 0x0B;
pub const BSL_CMD_READ_FLASH_TYPE: u16 = 0x0C;
pub const BSL_CMD_READ_FLASH_INFO: u16 = 0x0D;
pub const BSL_CMD_READ_SECTOR_SIZE: u16 = 0x0F;
pub const BSL_CMD_READ_START: u16 = 0x10;
pub const BSL_CMD_READ_MIDST: u16 = 0x11;
pub const BSL_CMD_READ_END: u16 = 0x12;

pub const BSL_CMD_KEEP_CHARGE: u16 = 0x13;
pub const BSL_CMD_EXTTABLE: u16 = 0x14;
pub const BSL_CMD_READ_FLASH_UID: u16 = 0x15;
pub const BSL_CMD_READ_SOFTSIM_EID: u16 = 0x16;
pub const BSL_CMD_POWER_OFF: u16 = 0x17;
pub const BSL_CMD_CHECK_ROOT: u16 = 0x19;
pub const BSL_CMD_READ_CHIP_UID: u16 = 0x1A;
pub const BSL_CMD_ENABLE_WRITE_FLASH: u16 = 0x1B;
pub const BSL_CMD_ENABLE_SECUREBOOT: u16 = 0x1C;
pub const BSL_CMD_IDENTIFY_START: u16 = 0x1D;
pub const BSL_CMD_IDENTIFY_END: u16 = 0x1E;
pub const BSL_CMD_READ_CU_REF: u16 = 0x1F;
pub const BSL_CMD_READ_REFINFO: u16 = 0x20;
pub const BSL_CMD_DISABLE_TRANSCODE: u16 = 0x21;
pub const BSL_CMD_WRITE_APR_INFO: u16 = 0x22;
pub const BSL_CMD_CUST_DUMMY: u16 = 0x23;
pub const BSL_CMD_READ_RF_TRANSCEIVER_TYPE: u16 = 0x24;
pub const BSL_CMD_ENABLE_DEBUG_MODE: u16 = 0x25;
pub const BSL_CMD_DDR_CHECK: u16 = 0x26;
pub const BSL_CMD_SELF_REFRESH: u16 = 0x27;
pub const BSL_CMD_ENABLE_RAW_DATA: u16 = 0x28;
pub const BSL_CMD_READ_NAND_BLOCK_INFO: u16 = 0x29;

pub const BSL_CMD_SET_FIRST_MODE: u16 = 0x2A;
pub const BSL_CMD_SET_RANDOM_DATA: u16 = 0x2B;
pub const BSL_CMD_SET_TIME_STAMP: u16 = 0x2C;
pub const BSL_CMD_READ_PARTITION: u16 = 0x2D;
pub const BSL_CMD_READ_VCUR_DATA: u16 = 0x2E;
pub const BSL_CMD_WRITE_VPAC_DATA: u16 = 0x2F;

pub const BSL_CMD_MIDST_RAW_START: u16 = 0x31;
pub const BSL_CMD_FLUSH_DATA: u16 = 0x32;
pub const BSL_CMD_MIDST_RAW_START2: u16 = 0x33;
pub const BSL_CMD_ENABLE_UBOOT_LOG: u16 = 0x34;
pub const BSL_CMD_DUMP_UBOOT_LOG: u16 = 0x35;

pub const BSL_CMD_DISABLE_SELINUX: u16 = 0x40;
pub const BSL_CMD_AUTH_BEGIN: u16 = 0x41;
pub const BSL_CMD_AUTH_END: u16 = 0x42;
pub const BSL_CMD_EMMC_CID: u16 = 0x43;
pub const BSL_CMD_OPEN_WATCH_DOG: u16 = 0x44;
pub const BSL_CMD_CLOSE_WATCH_DOG: u16 = 0x45;
pub const BSL_CMD_POWEROFF_NOKEY: u16 = 0x46;
pub const BSL_CMD_WRITE_EFUSE: u16 = 0x47;
pub const BSL_CMD_READ_PARTITION_VALUE: u16 = 0x48;
pub const BSL_CMD_WRITE_PARTITION_VALUE: u16 = 0x49;
pub const BSL_CMD_WRITE_DOWNLOAD_TIMESTAMP: u16 = 0x50;
pub const BSL_CMD_PARTITION_SIGNATURE: u16 = 0x51;

pub const BSL_CMD_SEND_FLAG: u16 = 0xCC;
pub const BSL_CMD_CHECK_BAUD: u16 = 0x7E;
pub const BSL_CMD_END_PROCESS: u16 = 0x7F;

// Responses
pub const BSL_REP_ACK: u16 = 0x80;
pub const BSL_REP_VER: u16 = 0x81;
pub const BSL_REP_INVALID_CMD: u16 = 0x82;
pub const BSL_REP_UNKNOW_CMD: u16 = 0x83;
pub const BSL_REP_OPERATION_FAILED: u16 = 0x84;
pub const BSL_REP_NOT_SUPPORT_BAUDRATE: u16 = 0x85;
pub const BSL_REP_DOWN_NOT_START: u16 = 0x86;
pub const BSL_REP_DOWN_MULTI_START: u16 = 0x87;
pub const BSL_REP_DOWN_EARLY_END: u16 = 0x88;
pub const BSL_REP_DOWN_DEST_ERROR: u16 = 0x89;
pub const BSL_REP_DOWN_SIZE_ERROR: u16 = 0x8A;
pub const BSL_REP_VERIFY_ERROR: u16 = 0x8B;
pub const BSL_REP_NOT_VERIFY: u16 = 0x8C;
pub const BSL_PHONE_NOT_ENOUGH_MEMORY: u16 = 0x8D;
pub const BSL_PHONE_WAIT_INPUT_TIMEOUT: u16 = 0x8E;
pub const BSL_PHONE_SUCCEED: u16 = 0x8F;
pub const BSL_PHONE_VALID_BAUDRATE: u16 = 0x90;
pub const BSL_PHONE_REPEAT_CONTINUE: u16 = 0x91;
pub const BSL_PHONE_REPEAT_BREAK: u16 = 0x92;

pub const BSL_REP_READ_FLASH: u16 = 0x93;
pub const BSL_REP_READ_CHIP_TYPE: u16 = 0x94;
pub const BSL_REP_READ_NVITEM: u16 = 0x95;
pub const BSL_REP_INCOMPATIBLE_PARTITION: u16 = 0x96;
pub const BSL_REP_UNKNOWN_DEVICE: u16 = 0x97;
pub const BSL_REP_INVALID_DEVICE_SIZE: u16 = 0x98;
pub const BSL_REP_ILLEGAL_SDRAM: u16 = 0x99;
pub const BSL_WRONG_SDRAM_PARAMETER: u16 = 0x9A;
pub const BSL_REP_READ_FLASH_INFO: u16 = 0x9B;
pub const BSL_REP_READ_SECTOR_SIZE: u16 = 0x9C;
pub const BSL_REP_READ_FLASH_TYPE: u16 = 0x9D;
pub const BSL_REP_READ_FLASH_UID: u16 = 0x9E;
pub const BSL_REP_READ_SOFTSIM_EID: u16 = 0x9F;

pub const BSL_ERROR_CHECKSUM: u16 = 0xA0;
pub const BSL_CHECKSUM_DIFF: u16 = 0xA1;
pub const BSL_WRITE_ERROR: u16 = 0xA2;
pub const BSL_CHIPID_NOT_MATCH: u16 = 0xA3;
pub const BSL_FLASH_CFG_ERROR: u16 = 0xA4;
pub const BSL_REP_DOWN_STL_SIZE_ERROR: u16 = 0xA5;
pub const BSL_REP_PHONE_IS_ROOTED: u16 = 0xA7;
pub const BSL_REP_SEC_VERIFY_ERROR: u16 = 0xAA;
pub const BSL_REP_READ_CHIP_UID: u16 = 0xAB;
pub const BSL_REP_NOT_ENABLE_WRITE_FLASH: u16 = 0xAC;
pub const BSL_REP_ENABLE_SECUREBOOT_ERROR: u16 = 0xAD;
pub const BSL_REP_IDENTIFY_START: u16 = 0xAE;
pub const BSL_REP_IDENTIFY_END: u16 = 0xAF;
pub const BSL_REP_READ_CU_REF: u16 = 0xB0;
pub const BSL_REP_READ_REFINFO: u16 = 0xB1;
pub const BSL_REP_CUST_DUMMY: u16 = 0xB2;
pub const BSL_REP_FLASH_WRITTEN_PROTECTION: u16 = 0xB3;
pub const BSL_REP_FLASH_INITIALIZING_FAIL: u16 = 0xB4;
pub const BSL_REP_RF_TRANSCEIVER_TYPE: u16 = 0xB5;
pub const BSL_REP_DDR_CHECK_ERROR: u16 = 0xB6;
pub const BSL_REP_SELF_REFRESH_ERROR: u16 = 0xB7;
pub const BSL_REP_READ_NAND_BLOCK_INFO: u16 = 0xB8;
pub const BSL_REP_RANDOM_DATA_ERROR: u16 = 0xB9;
pub const BSL_REP_READ_PARTITION: u16 = 0xBA;
pub const BSL_REP_DUMP_UBOOT_LOG: u16 = 0xBB;
pub const BSL_REP_READ_VCUR_DATA: u16 = 0xBC;
pub const BSL_REP_AUTH_M1_DATA: u16 = 0xBD;
pub const BSL_REP_READ_PARTITION_VALUE: u16 = 0xBE;
pub const BSL_REP_UNSUPPORT_PARTITION: u16 = 0xBF;
pub const BSL_REP_EMMC_CID_DATA: u16 = 0xC0;

pub const BSL_REP_MAGIC_ERROR: u16 = 0xD0;
pub const BSL_REP_REPARTITION_ERROR: u16 = 0xD1;
pub const BSL_REP_READ_FLASH_ERROR: u16 = 0xD2;
pub const BSL_REP_MALLOC_ERROR: u16 = 0xD3;

// EXTENDED Commands
pub const BSL_CMD_E_READ_MEM: u16 = 0x70;
pub const BSL_CMD_E_BL: u16 = 0x71;
pub const BSL_CMD_E_RPMB_PAGECOUNT: u16 = 0x73;
pub const BSL_CMD_E_RPMB_COUNTER: u16 = 0x74;
pub const BSL_CMD_E_RPMB_READ: u16 = 0x75;
pub const BSL_CMD_E_RPMB_WRITE: u16 = 0x76;
pub const BSL_CMD_E_PWN: u16 = 0x79;
pub const BSL_CMD_E_CHECKPWN: u16 = 0x7A;
pub const BSL_CMD_E_EFUSE_READ: u16 = 0x78;

// EXTENDED Responses
pub const BSL_REP_E_READ_MEM: u16 = 0xE0;
pub const BSL_REP_E_BL: u16 = 0xE1;
pub const BSL_REP_E_RPMB_PAGECOUNT: u16 = 0xE3;
pub const BSL_REP_E_RPMB_COUNTER: u16 = 0xE4;
pub const BSL_REP_E_RPMB_READ: u16 = 0xE5;
pub const BSL_REP_E_EFUSE_READ: u16 = 0xE8;

pub const BSL_REP_UNSUPPORTED_COMMAND: u16 = 0xFE;
pub const BSL_REP_LOG: u16 = 0xFF;
