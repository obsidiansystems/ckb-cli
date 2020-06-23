use ledger::ApduCommand;

pub fn app_version() -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x00,
        p1: 0x00,
        p2: 0x00,
        length: 0,
        data: Vec::new(),
    }
}

pub fn app_git_hash() -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x09,
        p1: 0x00,
        p2: 0x00,
        length: 0,
        data: Vec::new(),
    }
}

pub fn extend_public_key(data: Vec<u8>) -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x02,
        p1: 0x00,
        p2: 0x00,
        length: data.len() as u8,
        data,
    }
}

pub fn get_extended_public_key(data: Vec<u8>) -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x04,
        p1: 0x00,
        p2: 0x00,
        length: data.len() as u8,
        data,
    }
}

// BIP44 account_index, starts 0
pub fn do_account_import(account_index: u32) -> ledger::ApduCommand {
    let mut vec = Vec::new();
    vec.extend_from_slice(&account_index.to_be_bytes());
    ApduCommand {
        cla: 0x80,
        ins: 0x05,
        p1: 0x00,
        p2: 0x00,
        length: 4,
        data: vec,
    }
}

pub fn get_wallet_id() -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x01,
        p1: 0x00,
        p2: 0x00,
        length: 0,
        data: Vec::new(),
    }
}

pub fn sign_message(vec: Vec<u8>) -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x06,
        p1: 0x00,
        p2: 0x00,
        length: vec.len() as u8,
        data: vec,
    }
}
