use std::collections::HashMap;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::fs;
use std::io::prelude::{Write, Read};
use std::convert::TryInto;
use std::str::FromStr;

use bitflags;
use byteorder::{BigEndian, WriteBytesExt};
use either::Either;
use log::debug;
use secp256k1::{key::PublicKey, recovery::RecoverableSignature, recovery::RecoveryId, Signature};

use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_sdk::wallet::{
    is_valid_derivation_path, AbstractKeyStore, AbstractMasterPrivKey, AbstractPrivKey,
    ChildNumber, DerivationPath, DerivedKeySet, ScryptType, ExtendedPubKey, ChainCode, Fingerprint, KeyChain, SearchDerivedAddrFailed
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
    discovered_devices: HashMap<LedgerId, Arc<RawLedgerApp>>,
    imported_accounts: HashMap<H160, LedgerMasterCap>,
}

#[derive(Clone)]
struct LedgerImportedAccount {
    ledger_id: LedgerId,
    lock_arg: H160,
    ext_pub_key_root: ExtendedPubKey,
}

#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
// TODO make contain actual id to distinguish between ledgers
pub struct LedgerId(pub H256);

impl LedgerKeyStore {
    fn new(dir: PathBuf) -> Self {
        LedgerKeyStore {
            data_dir: dir.clone(),
            discovered_devices: HashMap::new(),
            imported_accounts: HashMap::new(),
        }
    }

    fn refresh(&mut self) -> Result<(), LedgerKeyStoreError> {
        // HACK: since we only support one ledger device
        // Dont scan again if we already have the device known.
        // This is needed to avoid creating a new RawLedgerApp
        // as it does not support multiple objects.
        let has_ledger_device_account = self.imported_accounts.values().any(|cap| cap.ledger_app.is_some());

        if !has_ledger_device_account {
            self.discovered_devices.clear();
            // We need to check for imported accounts first
            self.refresh_dir()?;
            // TODO fix ledger library so can put in all ledgers
            if let Ok(raw_ledger_app) = RawLedgerApp::new() {
                let command = apdu::get_wallet_id();
                let response = raw_ledger_app.exchange(command)?;
                debug!("Nervos CKB Ledger app wallet id: {:02x?}", response);

                let mut resp = &response.data[..];
                // TODO: The ledger app gives us 64 bytes but we only use 32
                // bytes. We should either limit how many the ledger app
                // gives, or take all 64 bytes here.
                let raw_wallet_id = parse::split_off_at(&mut resp, 32)?;
                let _ = parse::split_off_at(&mut resp, 32)?;
                parse::assert_nothing_left(resp)?;

                let ledger_id = LedgerId(H256::from_slice(raw_wallet_id).unwrap());
                let maybe_cap = self.imported_accounts.values()
                    .find(|cap| cap.account.ledger_id.clone() == ledger_id);
                match maybe_cap{
                    Some (cap) => {
                        if cap.ledger_app.is_none() {
                            let account = cap.account.clone();
                            self.imported_accounts.insert(account.lock_arg.clone(), LedgerMasterCap {
                                account: account,
                                ledger_app: Some (Arc::new(raw_ledger_app)),
                            });
                        } // else dont do anything
                        ()
                    },
                    _ => {
                        self.discovered_devices
                            .insert(ledger_id.clone(), Arc::new(raw_ledger_app));
                        ()
                    },
                };

            }
        }
        Ok(())
    }

    fn refresh_dir(&mut self) -> Result<(), LedgerKeyStoreError> {
        for entry in fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let mut file = fs::File::open(&path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let account = ledger_imported_account_from_json(&contents)?;
                match self.imported_accounts.get(&account.lock_arg) {
                    Some (_) => (),
                    None => {
                        self.imported_accounts.insert(account.lock_arg.clone(), LedgerMasterCap {account, ledger_app: None });
                        ()
                    },
                }
            }
        }
        Ok(())
    }

    pub fn discovered_devices<'a>(
        &'a mut self,
    ) -> Result<Box<dyn Iterator<Item = LedgerId>>, LedgerKeyStoreError> {
        self.refresh()?;
        let accounts: Vec<_> = self.discovered_devices.keys().cloned().collect();
        Ok(Box::new(accounts.into_iter()))
    }

    pub fn import_account<'a, 'b>(
        &'a mut self,
        account_id: &'b LedgerId,
    ) -> Result<H160, LedgerKeyStoreError> {
        self.refresh()?;
        let ledger_app = self.discovered_devices
            .remove(account_id)
            .ok_or_else(|| LedgerKeyStoreError::LedgerNotFound {
                id: account_id.clone(),
            })?;
        let bip_account_index = 0;
        let command = apdu::do_account_import(bip_account_index);
        let response = ledger_app.exchange(command)?;

        debug!(
            "Nervos CBK Ledger app extended pub key raw public key {:02x?}",
            &response
        );
        let mut resp = &response.data[..];

        let len1 = parse::split_first(&mut resp)? as usize;
        let raw_public_key = parse::split_off_at(&mut resp, len1)?;
        let len2 = parse::split_first(&mut resp)? as usize;
        let chain_code = parse::split_off_at(&mut resp, len2)?;
        parse::assert_nothing_left(resp)?;
        let public_key = PublicKey::from_slice(&raw_public_key)?;
        let chain_code = ChainCode(chain_code.try_into().expect("chain_code is not 32 bytes"));
        let path = DerivationPath::from_str("m/44'/309'/0'").unwrap();
        let ext_pub_key_root = ExtendedPubKey {
            depth: path.as_ref().len() as u8,
            parent_fingerprint: {
                let mut engine = hash160::Hash::engine();
                engine
                    .write_all(b"`parent_fingerprint` currently unused by Nervos.")
                    .expect("write must ok");
                Fingerprint::from(&hash160::Hash::from_engine(engine)[0..4])
            },
            child_number: ChildNumber::Hardened { index: 0 },
            public_key,
            chain_code,
        };
        let LedgerId (ledger_id) = account_id;
        let filepath = self.data_dir.join(ledger_id.to_string());
        let lock_arg = ckb_sdk::wallet::hash_public_key(&public_key);
        let account = LedgerImportedAccount {
            ledger_id: account_id.clone(),
            lock_arg: lock_arg.clone(),
            ext_pub_key_root,
        };
        let json_value = ledger_imported_account_to_json(&account)?;
        self.imported_accounts.insert(lock_arg.clone(), LedgerMasterCap {account, ledger_app: Some (ledger_app)});
        fs::File::create(&filepath)
            .and_then(|mut file| file.write_all(json_value.to_string().as_bytes()))
            .map_err(|err| LedgerKeyStoreError::KeyStoreIOError(err))?;
        Ok(lock_arg)
    }

}

impl AbstractKeyStore for LedgerKeyStore {
    const SOURCE_NAME: &'static str = "ledger hardware wallet";

    type Err = LedgerKeyStoreError;

    type AccountId = H160;

    type AccountCap = LedgerMasterCap;

    fn list_accounts(&mut self) -> Result<Box<dyn Iterator<Item = Self::AccountId>>, Self::Err> {
        self.refresh()?;
        let accounts: Vec<_> = self.imported_accounts.keys().cloned().collect();
        Ok(Box::new(accounts.into_iter()))
    }

    fn from_dir(dir: PathBuf, _scrypt_type: ScryptType) -> Result<Self, LedgerKeyStoreError> {
        // let abs_dir = dir.canonicalize()?;
        // TODO maybe force the initialization of the HidAPI "lazy static"?
        Ok(LedgerKeyStore::new(dir))
    }

    fn borrow_account<'a, 'b>(
        &'a mut self,
        lock_arg: &'b Self::AccountId,
    ) -> Result<&'a Self::AccountCap, Self::Err> {
        self.refresh()?;
        self.imported_accounts
            .get(lock_arg)
            .ok_or_else(|| LedgerKeyStoreError::LedgerAccountNotFound (lock_arg.clone()))
    }
}

/// A ledger device with the Nervos app.
#[derive(Clone)]
pub struct LedgerMasterCap {
    account: LedgerImportedAccount,
    // TODO no Arc once we have "generic associated types" and can just borrow the device.
    ledger_app: Option <Arc<RawLedgerApp>>,

}

impl LedgerMasterCap {
    pub fn derive_extended_public_key(
        &self,
        chain: KeyChain,
        index: ChildNumber,
    ) -> ExtendedPubKey {
        let epk = match chain {
            KeyChain::External => self.account.ext_pub_key_root.ckd_pub(&SECP256K1, ChildNumber::Normal { index: 0}).unwrap(),
            KeyChain::Change => self.account.ext_pub_key_root.ckd_pub(&SECP256K1, ChildNumber::Normal { index: 1}).unwrap()
        };
        epk.ckd_pub(&SECP256K1, index).unwrap()
    }

    pub fn derived_key_set_by_index(
        &self,
        external_start: u32,
        external_length: u32,
        change_start: u32,
        change_length: u32,
    ) -> DerivedKeySet {
        let get_pairs = |chain, start, length| {

            (0..length)
                .map(|i| {
                    let path_string = format!("m/44'/309'/0'/{}/{}", chain as u8, i + start);
                    let path = DerivationPath::from_str(path_string.as_str()).unwrap();
                    let extended_pubkey = self.derive_extended_public_key(chain, ChildNumber::from(i + start));
                    let pubkey = extended_pubkey.public_key;
                    let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
                        .expect("Generate hash(H160) from pubkey failed");
                    (path, hash)
                })
                .into_iter()
                .collect::<Vec<_>>()
        };
        DerivedKeySet {
            external: get_pairs(KeyChain::External, external_start, external_length),
            change: get_pairs(KeyChain::Change, change_start, change_length),
        }
    }

    pub fn get_root_pubkey(&self) -> PublicKey {
        return self.account.ext_pub_key_root.public_key;
    }

    pub fn get_extended_pubkey(&self, path: &[ChildNumber]) -> Result<ExtendedPubKey, LedgerKeyStoreError> {
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
        let ledger_app = self.ledger_app.as_ref().ok_or(LedgerKeyStoreError::LedgerNotFound { id: self.account.ledger_id.clone() })?;
        let response = ledger_app.exchange(command)?;
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

    pub fn sign_message(&self, message: &[u8]) -> Result<Signature, LedgerKeyStoreError> {
        let message_vec : Vec<u8> = message.iter().cloned().collect();
        let my_self = self.clone();
        let chunk = |mut message: &[u8]| -> Result<_, LedgerKeyStoreError> {
            assert!(message.len() > 0, "initial message must be non-empty");

            // Init packet provides only the account index
            let ledger_app = my_self.ledger_app.as_ref()
                .ok_or(LedgerKeyStoreError::LedgerNotFound { id: my_self.account.ledger_id.clone()})?;
            // Only support account index 0 for now
            let init_apdu = apdu::sign_message(SignP1::FIRST.bits, [0, 0, 0, 0].to_vec()); //send uint32_t
            let _ = ledger_app.exchange(init_apdu);


            let mut base = SignP1::NEXT;
            loop {
                let length = ::std::cmp::min(message.len(), MAX_APDU_SIZE);
                let chunk = parse::split_off_at(&mut message, length)?;
                let rest_length = message.len();
                let p1 = (if rest_length > 0 {
                        base
                    } else {
                        base | SignP1::LAST_MARKER
                    })
                    .bits;
                let command = apdu::sign_message(p1, chunk.to_vec());
                let response = ledger_app.exchange(command)?;
                if rest_length == 0 {
                    return Ok(response);
                }
                base = SignP1::NEXT;
            }
        };
        let response = chunk(message_vec.as_slice().as_ref())?;
        let raw_signature = response.data.clone();
        let mut resp = &raw_signature[..];
        let data = parse::split_off_at(&mut resp, 64)?;
        let recovery_id = RecoveryId::from_i32(parse::split_first(&mut resp)? as i32)?;
        parse::assert_nothing_left(resp)?;
        let rec_sig = RecoverableSignature::from_compact(data, recovery_id)?;
        // Convert to non-recoverable
        return Ok(rec_sig.to_standard());
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

    fn derived_key_set(
        &self,
        external_max_len: u32,
        change_last: &H160,
        change_max_len: u32,
    ) -> Result<DerivedKeySet, Either<Self::Err, SearchDerivedAddrFailed>> {
        let mut external_key_set = Vec::new();
        for i in 0..external_max_len {
            let path_string = format!("m/44'/309'/0'/{}/{}", KeyChain::External as u8, i);
            let path = DerivationPath::from_str(path_string.as_str()).unwrap();
            let epk = self.account.ext_pub_key_root.ckd_pub(&SECP256K1, ChildNumber::Normal { index: 0}).unwrap();
            let extended_pubkey = epk.ckd_pub(&SECP256K1, ChildNumber::Normal { index: i}).unwrap();
            let pubkey = extended_pubkey.public_key;
            let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
                .expect("Generate hash(H160) from pubkey failed");
            external_key_set.push((path, hash));
        }

        let mut change_key_set = Vec::new();
        for i in 0..change_max_len {
            let path_string = format!("m/44'/309'/0'/{}/{}", KeyChain::Change as u8, i);
            let path = DerivationPath::from_str(path_string.as_str()).unwrap();
            let epk = self.account.ext_pub_key_root.ckd_pub(&SECP256K1, ChildNumber::Normal { index: 1}).unwrap();
            let extended_pubkey = epk.ckd_pub(&SECP256K1, ChildNumber::Normal { index: i}).unwrap();
            let pubkey = extended_pubkey.public_key;
            let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
                .expect("Generate hash(H160) from pubkey failed");
            change_key_set.push((path, hash.clone()));
            if change_last == &hash {
                return Ok(DerivedKeySet {
                    external: external_key_set,
                    change: change_key_set,
                });
            }
        }
        Err(Either::Right(SearchDerivedAddrFailed))
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

    // Tries to derive from extended_pubkey if possible
    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        let account_root_path = DerivationPath::from_str("m/44'/309'/0'").unwrap();
        if self.path == account_root_path {
            Ok (self.master.account.ext_pub_key_root.public_key)
        } else {
            let my_path_v: Vec<ChildNumber> = self.path.clone().into();

            // TODO: store account_id and get rid of hardcoded account here
            let account_root_v: Vec<ChildNumber> = account_root_path.into();
            let same_account = account_root_v.iter().zip(my_path_v.iter())
                .all(|(c1, c2)| c1 == c2);

            let maybe_chain_index = if same_account && my_path_v.len() == 5 {
                (if my_path_v[3] == ChildNumber::from(0) {
                    Some (KeyChain::External)
                } else if my_path_v[3] == ChildNumber::from(1) {
                    Some (KeyChain::Change)
                } else {
                    None
                }).map (|c| {
                    (c, my_path_v[4])
                })
            } else {
                None
            };
            match maybe_chain_index {
                Some ((c, i)) => Ok(self.master.derive_extended_public_key(c, i).public_key),
                None => self.public_key_prompt()
            }
        }
    }

    fn public_key_prompt(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        let mut data = Vec::new();
        data.write_u8(self.path.as_ref().len() as u8)
            .expect(WRITE_ERR_MSG);
        for &child_num in self.path.as_ref().iter() {
            data.write_u32::<BigEndian>(From::from(child_num))
                .expect(WRITE_ERR_MSG);
        }
        let command = apdu::extend_public_key(data);
        let ledger_app = self.master.ledger_app.as_ref().ok_or(LedgerKeyStoreError::LedgerNotFound { id: self.master.account.ledger_id.clone() })?;
        let response = ledger_app.exchange(command)?;
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

    fn sign(&self, _message: &[u8]) -> Result<Signature, Self::Err> {
         unimplemented!("Need to generalize method to not take hash")
        // let signature = self.sign_recoverable(message)?;
        // Ok(RecoverableSignature::to_standard(&signature))
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
                    let ledger_app = my_self.master.ledger_app.as_ref()
                        .ok_or(LedgerKeyStoreError::LedgerNotFound { id: my_self.master.account.ledger_id.clone()})?;
                    let response = ledger_app.exchange(ApduCommand {
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
    extended_public_key_root: LedgerAccountExtendedPubKeyJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerAccountExtendedPubKeyJson {
    address: String,
    chain_code: [u8;32],
}

fn ledger_imported_account_to_json ( inp: &LedgerImportedAccount) -> Result<serde_json::Value, serde_json::error::Error> {
    let LedgerId (ledger_id) = inp.ledger_id.clone();
    let lock_arg = inp.lock_arg.clone();
    let extended_public_key_root = LedgerAccountExtendedPubKeyJson {
        address: inp.ext_pub_key_root.public_key.to_string(),
        chain_code: (|ChainCode (bytes)| bytes) (inp.ext_pub_key_root.chain_code),
    };
    serde_json::to_value(LedgerAccountJson {
        ledger_id,
        lock_arg,
        extended_public_key_root,
    })
}

fn ledger_imported_account_from_json ( inp: &String) -> Result<LedgerImportedAccount, LedgerKeyStoreError> {

    let acc: LedgerAccountJson = serde_json::from_str(inp)?;
    let ext_pub_key_root = {
        let path = DerivationPath::from_str("m/44'/309'/0'").unwrap();
        let public_key = PublicKey::from_str(&acc.extended_public_key_root.address)?;
        let chain_code = ChainCode(acc.extended_public_key_root.chain_code);
        ExtendedPubKey {
            depth: path.as_ref().len() as u8,
            parent_fingerprint: {
                let mut engine = hash160::Hash::engine();
                engine
                    .write_all(b"`parent_fingerprint` currently unused by Nervos.")
                    .expect("write must ok");
                Fingerprint::from(&hash160::Hash::from_engine(engine)[0..4])
            },
            child_number: ChildNumber::Hardened { index: 0 },
            public_key,
            chain_code,
        }
    };

    Ok(LedgerImportedAccount {
        ledger_id : LedgerId (acc.ledger_id),
        lock_arg: acc.lock_arg,
        ext_pub_key_root,
    })
}
