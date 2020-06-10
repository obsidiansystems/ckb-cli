use std::collections::HashMap;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::fs;
use std::io::prelude::{Write};
use std::convert::TryInto;
use std::str::FromStr;

use bitflags;
use byteorder::{BigEndian, WriteBytesExt};
use log::debug;
use secp256k1::{key::PublicKey, recovery::RecoverableSignature, recovery::RecoveryId, Signature};

use ckb_sdk::wallet::{
    is_valid_derivation_path, AbstractKeyStore, AbstractMasterPrivKey, AbstractPrivKey,
    ChildNumber, DerivationPath, ScryptType, ExtendedPubKey, ChainCode, Fingerprint,
};
use ckb_sdk::SignEntireHelper;
use ckb_types::{H160, H256};
use bitcoin_hashes::{hash160, Hash};
use serde::{Deserialize, Serialize};

use ledger::ApduCommand;
use ledger::LedgerApp as RawLedgerApp;

pub mod apdu;
mod error;
pub mod parse;

pub use error::Error as LedgerKeyStoreError;

use ckb_types::{
    packed::{AnnotatedTransaction, Bip32, Uint32},
    prelude::*,
};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub struct LedgerKeyStore {
    data_dir: PathBuf, // For storing extended public keys, never stores any private key
    discovered_devices: HashMap<LedgerId, LedgerMasterCap>,
}

struct LedgerImportedAccount {
    ledger_id: LedgerId,
    lock_arg: H160,
    ext_pub_key_normal: ExtendedPubKey,
    ext_pub_key_change: ExtendedPubKey,
}

#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
// TODO make contain actual id to distinguish between ledgers
pub struct LedgerId(pub H256);

impl LedgerKeyStore {
    fn new(dir: PathBuf) -> Self {
        LedgerKeyStore {
            data_dir: dir.clone(),
            discovered_devices: HashMap::new(),
        }
    }

    fn refresh(&mut self) -> Result<(), LedgerKeyStoreError> {
        self.discovered_devices.clear();
        // TODO fix ledger library so can put in all ledgers
        if let Ok(raw_ledger_app) = RawLedgerApp::new() {
            let ledger_app = LedgerMasterCap::from_ledger(raw_ledger_app)?;
            self.discovered_devices
                .insert(ledger_app.id.clone(), ledger_app);
        }
        Ok(())
    }

    pub fn import_account<'a, 'b>(
        &'a mut self,
        account_id: &'b LedgerId,
    ) -> Result<H160, LedgerKeyStoreError> {
        self.refresh()?;
        let ledger_app = self.discovered_devices
            .get(account_id)
            .ok_or_else(|| LedgerKeyStoreError::LedgerNotFound {
                id: account_id.clone(),
            })?;
        let bip_account_id = 0;
        let bip_account_path_string = format!("m/44'/309'/{}'", bip_account_id);
        let normal_path_string = format!("m/44'/309'/{}'/{}", bip_account_id, 0);
        let change_path_string = format!("m/44'/309'/{}'/{}", bip_account_id, 1);
        let bip_account_path = DerivationPath::from_str(bip_account_path_string.as_str()).unwrap();
        let normal_path = DerivationPath::from_str(normal_path_string.as_str()).unwrap();
        let change_path = DerivationPath::from_str(change_path_string.as_str()).unwrap();

        let pub_key_normal = ledger_app.extended_privkey(bip_account_path.as_ref())?.public_key()?;
        let ext_pub_key_normal = ledger_app.extended_pubkey(normal_path.as_ref())?;
        let ext_pub_key_change = ledger_app.extended_pubkey(change_path.as_ref())?;

        let LedgerId (ledger_id) = account_id;
        let filepath = self.data_dir.join(ledger_id.to_string());
        let lock_arg = ckb_sdk::wallet::hash_public_key(&pub_key_normal);
        let ext_pub_key_normal = serde_json::json!({
            "address" : ext_pub_key_normal.public_key.to_string(),
            "chain-code" : (|ChainCode (bytes)| bytes) (ext_pub_key_normal.chain_code),
        });
        let ext_pub_key_change = serde_json::json!({
            "address" : ext_pub_key_change.public_key.to_string(),
            "chain-code" : (|ChainCode (bytes)| bytes) (ext_pub_key_change.chain_code),
        });
        let json_value = serde_json::json!({
            "ledger-id" : ledger_id,
            "lock_arg" : lock_arg,
            "extended_public_key_normal": ext_pub_key_normal,
            "extended_public_key_change": ext_pub_key_change,
        });
        fs::File::create(&filepath)
            .and_then(|mut file| file.write_all(json_value.to_string().as_bytes()))
            .map_err(|err| LedgerKeyStoreError::KeyStoreIOError{err})?;
        Ok(lock_arg)
    }

}

impl AbstractKeyStore for LedgerKeyStore {
    const SOURCE_NAME: &'static str = "ledger hardware wallet";

    type Err = LedgerKeyStoreError;

    type AccountId = LedgerId;

    type AccountCap = LedgerMasterCap;

    fn list_accounts(&mut self) -> Result<Box<dyn Iterator<Item = Self::AccountId>>, Self::Err> {
        self.refresh()?;
        let key_copies: Vec<_> = self.discovered_devices.keys().cloned().collect();
        Ok(Box::new(key_copies.into_iter()))
    }

    fn from_dir(dir: PathBuf, _scrypt_type: ScryptType) -> Result<Self, LedgerKeyStoreError> {
        // let abs_dir = dir.canonicalize()?;
        // TODO maybe force the initialization of the HidAPI "lazy static"?
        Ok(LedgerKeyStore::new(dir))
    }

    fn borrow_account<'a, 'b>(
        &'a mut self,
        account_id: &'b Self::AccountId,
    ) -> Result<&'a Self::AccountCap, Self::Err> {
        self.refresh()?;
        self.discovered_devices
            .get(account_id)
            .ok_or_else(|| LedgerKeyStoreError::LedgerNotFound {
                id: account_id.clone(),
            })
    }
}

/// A ledger device with the Nervos app.
#[derive(Clone)]
pub struct LedgerMasterCap {
    id: LedgerId,
    // TODO no Arc once we have "generic associated types" and can just borrow the device.
    ledger_app: Arc<RawLedgerApp>,
}

impl LedgerMasterCap {
    /// Create from a ledger device, checking that a proper version of the
    /// Nervos app is installed.
    fn from_ledger(ledger_app: RawLedgerApp) -> Result<Self, LedgerKeyStoreError> {
        let command = apdu::get_wallet_id();
        let response = ledger_app.exchange(command)?;
        debug!("Nervos CKB Ledger app wallet id: {:02x?}", response);

        let mut resp = &response.data[..];
        // TODO: The ledger app gives us 64 bytes but we only use 32
        // bytes. We should either limit how many the ledger app
        // gives, or take all 64 bytes here.
        let raw_wallet_id = parse::split_off_at(&mut resp, 32)?;
        let _ = parse::split_off_at(&mut resp, 32)?;
        parse::assert_nothing_left(resp)?;

        Ok(LedgerMasterCap {
            id: LedgerId(H256::from_slice(raw_wallet_id).unwrap()),
            ledger_app: Arc::new(ledger_app),
        })
    }
}

const WRITE_ERR_MSG: &'static str = "IO error not possible when writing to Vec last I checked";

impl AbstractMasterPrivKey for LedgerMasterCap {
    type Err = LedgerKeyStoreError;

    type Privkey = LedgerCap;

    fn extended_privkey(&self, path: &[ChildNumber]) -> Result<LedgerCap, Self::Err> {
        if !is_valid_derivation_path(path.as_ref()) {
            return Err(LedgerKeyStoreError::InvalidDerivationPath {
                path: path.as_ref().iter().cloned().collect(),
            });
        }

        Ok(LedgerCap {
            master: self.clone(),
            path: From::from(path.as_ref()),
        })
    }

    fn extended_pubkey(&self, path: &[ChildNumber]) -> Result<ExtendedPubKey, Self::Err> {
        if !is_valid_derivation_path(path.as_ref()) {
            return Err(LedgerKeyStoreError::InvalidDerivationPath {
                path: path.as_ref().iter().cloned().collect(),
            });
        }
        let mut data = Vec::new();
        data.write_u8(path.as_ref().len() as u8)
            .expect(WRITE_ERR_MSG);
        for &child_num in path.as_ref().iter() {
            data.write_u32::<BigEndian>(From::from(child_num))
                .expect(WRITE_ERR_MSG);
        }
        let command = apdu::get_extended_public_key(data);
        let response = self.ledger_app.exchange(command)?;
        debug!(
            "Nervos CBK Ledger app extended pub key raw public key {:02x?} for path {:?}",
            &response, &path
        );
        let mut resp = &response.data[..];
        let len1 = parse::split_first(&mut resp)? as usize;
        let raw_public_key = parse::split_off_at(&mut resp, len1)?;
        let len2 = parse::split_first(&mut resp)? as usize;
        let chain_code = parse::split_off_at(&mut resp, len2)?;
        parse::assert_nothing_left(resp)?;
        let public_key = PublicKey::from_slice(&raw_public_key)?;
        let chain_code = ChainCode(chain_code.try_into().expect("chain_code is not 32 bytes"));
        Ok (ExtendedPubKey {
            depth: path.as_ref().len() as u8,
            parent_fingerprint: {
                let mut engine = hash160::Hash::engine();
                engine
                    .write_all(b"`parent_fingerprint` currently unused by Nervos.")
                    .expect("write must ok");
                Fingerprint::from(&hash160::Hash::from_engine(engine)[0..4])
            },
            child_number: path
                .last()
                .unwrap_or(&ChildNumber::Hardened { index: 0 })
                .clone(),
            public_key,
            chain_code,
        })
    }
}

/// A ledger device with the Nervos app constrained to a specific derivation path.
#[derive(Clone)]
pub struct LedgerCap {
    master: LedgerMasterCap,
    pub path: DerivationPath,
}

// Only not using impl trait because unstable
type LedgerClosure = Box<dyn FnOnce(Vec<u8>) -> Result<RecoverableSignature, LedgerKeyStoreError>>;

const MAX_APDU_SIZE: usize = 230;

bitflags::bitflags! {
    struct SignP1: u8 {
        // for the path
        const FIRST = 0b_0000_0000;
        // for the tx
        const NEXT  = 0b_0000_0001;
        //const HASH_ONLY_NEXT  = 0b_000_0010 | Self::NEXT.bits; // You only need it once
        const CHANGE_PATH = 0b_0001_0000;
        const IS_CONTEXT = 0b_0010_0000;
        const NO_FALLBACK = 0b_0100_0000;
        const LAST_MARKER = 0b_1000_0000;
        const MASK = Self::LAST_MARKER.bits | Self::NO_FALLBACK.bits | Self::IS_CONTEXT.bits;
    }
}

impl AbstractPrivKey for LedgerCap {
    type Err = LedgerKeyStoreError;

    type SignerSingleShot = SignEntireHelper<LedgerClosure>;

    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        let mut data = Vec::new();
        data.write_u8(self.path.as_ref().len() as u8)
            .expect(WRITE_ERR_MSG);
        for &child_num in self.path.as_ref().iter() {
            data.write_u32::<BigEndian>(From::from(child_num))
                .expect(WRITE_ERR_MSG);
        }
        let command = apdu::extend_public_key(data);
        let response = self.master.ledger_app.exchange(command)?;
        debug!(
            "Nervos CBK Ledger app extended pub key raw public key {:02x?} for path {:?}",
            &response, &self.path
        );
        let mut resp = &response.data[..];
        let len = parse::split_first(&mut resp)? as usize;
        let raw_public_key = parse::split_off_at(&mut resp, len)?;
        parse::assert_nothing_left(resp)?;
        Ok(PublicKey::from_slice(&raw_public_key)?)
    }

    fn sign(&self, _message: &H256) -> Result<Signature, Self::Err> {
        unimplemented!("Need to generalize method to not take hash")
        //let signature = self.sign_recoverable(message)?;
        //Ok(RecoverableSignature::to_standard(&signature))
    }

    fn begin_sign_recoverable(&self) -> Self::SignerSingleShot {
        let my_self = self.clone();

        SignEntireHelper::new(Box::new(move |message: Vec<u8>| {
            debug!(
                "Sending Nervos CKB Ledger app message of {:02x?} with length {:?}",
                message,
                message.len()
            );

            // Need to fill in missing “path” from signer.
            let mut raw_path = Vec::<Uint32>::new();
            for &child_num in my_self.path.as_ref().iter() {
                let raw_child_num: u32 = child_num.into();
                let raw_path_bytes = raw_child_num.to_le_bytes();
                raw_path.push(
                    Uint32::new_builder()
                        .nth0(raw_path_bytes[0].into())
                        .nth1(raw_path_bytes[1].into())
                        .nth2(raw_path_bytes[2].into())
                        .nth3(raw_path_bytes[3].into())
                        .build(),
                )
            }

            let message_with_sign_path = AnnotatedTransaction::from_slice(&message).unwrap();
            let sign_path = Bip32::new_builder().set(raw_path).build();
            let change_path = if message_with_sign_path.change_path().len() == 0 {
                sign_path.clone()
            } else {
                message_with_sign_path.change_path()
            };

            let raw_message = message_with_sign_path
                .as_builder()
                .sign_path(sign_path)
                .change_path(change_path)
                .build();

            debug!(
                "Modified Nervos CKB Ledger app message of {:02x?} with length {:?}",
                raw_message.as_slice(),
                raw_message.as_slice().len()
            );

            let chunk = |mut message: &[u8]| -> Result<_, Self::Err> {
                assert!(message.len() > 0, "initial message must be non-empty");
                let mut base = SignP1::FIRST;
                loop {
                    let length = ::std::cmp::min(message.len(), MAX_APDU_SIZE);
                    let chunk = parse::split_off_at(&mut message, length)?;
                    let rest_length = message.len();
                    let response = my_self.master.ledger_app.exchange(ApduCommand {
                        cla: 0x80,
                        ins: 0x03,
                        p1: (if rest_length > 0 {
                            base
                        } else {
                            base | SignP1::LAST_MARKER
                        })
                        .bits,
                        p2: 0,
                        length: chunk.len() as u8,
                        data: chunk.to_vec(),
                    })?;
                    if rest_length == 0 {
                        return Ok(response);
                    }
                    base = SignP1::NEXT;
                }
            };

            let response = chunk(raw_message.as_slice().as_ref())?;

            debug!(
                "Received Nervos CKB Ledger result of {:02x?} with length {:?}",
                response.data,
                response.data.len()
            );

            let raw_signature = response.data.clone();
            let mut resp = &raw_signature[..];

            let data = parse::split_off_at(&mut resp, 64)?;
            let recovery_id = RecoveryId::from_i32(parse::split_first(&mut resp)? as i32)?;
            debug!("Recovery id is {:?}", recovery_id);
            parse::assert_nothing_left(resp)?;

            Ok(RecoverableSignature::from_compact(data, recovery_id)?)
        }))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerAccountJson {
    ledger_id: H256,
    lock_arg: H160,
    extended_public_key_normal: LedgerAccountExtendedPubKeyJson,
    extended_public_key_change: LedgerAccountExtendedPubKeyJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerAccountExtendedPubKeyJson {
    address: String,
    chain_code: [u8;32],
}

fn ledger_imported_account_to_json ( inp: &LedgerImportedAccount) -> Result<serde_json::Value, serde_json::error::Error> {
    let LedgerId (ledger_id) = inp.ledger_id.clone();
    let lock_arg = inp.lock_arg.clone();
    let extended_public_key_normal = LedgerAccountExtendedPubKeyJson {
        address: inp.ext_pub_key_normal.public_key.to_string(),
        chain_code: (|ChainCode (bytes)| bytes) (inp.ext_pub_key_normal.chain_code),
    };
    let extended_public_key_change = LedgerAccountExtendedPubKeyJson {
        address: inp.ext_pub_key_change.public_key.to_string(),
        chain_code: (|ChainCode (bytes)| bytes) (inp.ext_pub_key_change.chain_code),
    };
    serde_json::to_value(LedgerAccountJson {
        ledger_id,
        lock_arg,
        extended_public_key_normal,
        extended_public_key_change,
    })
}

fn ledger_imported_account_from_json ( inp: &String) -> Result<LedgerImportedAccount, LedgerKeyStoreError> {

    let acc: LedgerAccountJson = serde_json::from_str(inp)?;
    fn get_ext_pub_key (s: &LedgerAccountExtendedPubKeyJson, is_change: bool) -> Result< ExtendedPubKey, LedgerKeyStoreError> {
        let pub_key = PublicKey::from_str(&s.address)?;
        let chain_code = ChainCode(s.chain_code);
        Ok(to_ext_pub_key (pub_key, chain_code, is_change))
    };

    let ext_pub_key_normal = get_ext_pub_key(&acc.extended_public_key_normal, false)?;
    let ext_pub_key_change = get_ext_pub_key(&acc.extended_public_key_change, true)?;
    Ok(LedgerImportedAccount {
        ledger_id : LedgerId (acc.ledger_id),
        lock_arg: acc.lock_arg,
        ext_pub_key_normal,
        ext_pub_key_change,
    })
}

fn to_ext_pub_key (public_key: PublicKey, chain_code: ChainCode, is_change: bool) -> ExtendedPubKey {
    let i = if is_change { 1 } else { 0 };
    ExtendedPubKey {
        depth: 4,
        parent_fingerprint: {
            let mut engine = hash160::Hash::engine();
            engine
                .write_all(b"`parent_fingerprint` currently unused by Nervos.")
                .expect("write must ok");
            Fingerprint::from(&hash160::Hash::from_engine(engine)[0..4])
        },
        child_number: ChildNumber::Normal { index: i },
        public_key,
        chain_code,
    }
}
