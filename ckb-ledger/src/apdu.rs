use ledger_apdu::APDUCommand;

pub fn app_version() -> APDUCommand {
    APDUCommand {
        cla: 0x80,
        ins: 0x00,
        p1: 0x00,
        p2: 0x00,
        data: Vec::new(),
    }
}

pub fn app_git_hash() -> APDUCommand {
    APDUCommand {
        cla: 0x80,
        ins: 0x09,
        p1: 0x00,
        p2: 0x00,
        data: Vec::new(),
    }
}

pub fn extend_public_key(data: Vec<u8>) -> APDUCommand {
    APDUCommand {
        cla: 0x80,
        ins: 0x02,
        p1: 0x00,
        p2: 0x00,
        data,
    }
}

pub fn get_extended_public_key(data: Vec<u8>) -> APDUCommand {
    APDUCommand {
        cla: 0x80,
        ins: 0x04,
        p1: 0x00,
        p2: 0x00,
        data,
    }
}

// BIP44 account_index, starts 0
pub fn do_account_import(account_index: u32) -> APDUCommand {
    let mut vec = Vec::new();
    vec.extend_from_slice(&account_index.to_be_bytes());
    APDUCommand {
        cla: 0x80,
        ins: 0x05,
        p1: 0x00,
        p2: 0x00,
        data: vec,
    }
}

pub fn get_wallet_id() -> APDUCommand {
    APDUCommand {
        cla: 0x80,
        ins: 0x01,
        p1: 0x00,
        p2: 0x00,
        data: Vec::new(),
    }
}

pub fn sign_message(p1_byte: u8, vec: Vec<u8>) -> APDUCommand {
    APDUCommand {
        cla: 0x80,
        ins: 0x06,
        p1: p1_byte,
        p2: 0x00,
        data: vec,
    }
}

pub fn sign_message_hash(p1_byte: u8, vec: Vec<u8>) -> APDUCommand {
    APDUCommand {
        cla: 0x80,
        ins: 0x07,
        p1: p1_byte,
        p2: 0x00,
        data: vec,
    }
}
