use std::collections::HashMap;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use bitflags;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::debug;
use secp256k1::{key::PublicKey, recovery::RecoverableSignature, recovery::RecoveryId, Signature};

use ckb_sdk::wallet::{
    is_valid_derivation_path, AbstractKeyStore, AbstractMasterPrivKey, AbstractPrivKey,
    ChildNumber, DerivationPath, ScryptType,
};
use ckb_sdk::SignEntireHelper;
use ckb_types::H256;

use ledger::ApduCommand;
use ledger::LedgerApp as RawLedgerApp;

pub mod apdu;
mod error;
pub mod parse;

pub use error::Error as LedgerKeyStoreError;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub struct LedgerKeyStore {
    discovered_devices: HashMap<LedgerId, LedgerMasterCap>,
}

#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
// TODO make contain actual id to distinguish between ledgers
pub struct LedgerId(pub H256);

impl LedgerKeyStore {
    fn new() -> Self {
        LedgerKeyStore {
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

    fn from_dir(_dir: PathBuf, _scrypt_type: ScryptType) -> Result<Self, LedgerKeyStoreError> {
        // TODO maybe force the initialization of the HidAPI "lazy static"?
        Ok(LedgerKeyStore::new())
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

    type SingleShot = SignEntireHelper<LedgerClosure>;

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

    fn begin_sign_recoverable(&self) -> Self::SingleShot {
        let my_self = self.clone();

        SignEntireHelper::new(Box::new(move |message: Vec<u8>| {
            let mut message = message.as_ref();

            let mut raw_path = Vec::new();
            raw_path
                .write_u8(my_self.path.as_ref().len() as u8)
                .expect(WRITE_ERR_MSG);
            for &child_num in my_self.path.as_ref().iter() {
                raw_path
                    .write_u32::<BigEndian>(From::from(child_num))
                    .expect(WRITE_ERR_MSG);
            }

            let change_path_len = parse::split_first(&mut message)?;
            let raw_change_path = if change_path_len > 0 {
                let my_change_path =
                    parse::split_off_at(&mut message, 4 * change_path_len as usize)?.to_vec();
                debug!("Change path is {:02x?}", my_change_path);
                let mut path = Vec::new();
                path.push(change_path_len);
                path.extend(my_change_path);
                path
            } else {
                raw_path.clone()
            };

            my_self.master.ledger_app.exchange(ApduCommand {
                cla: 0x80,
                ins: 0x03,
                p1: SignP1::FIRST.bits,
                p2: 0,
                length: raw_path.len() as u8,
                data: raw_path,
            })?;

            my_self.master.ledger_app.exchange(ApduCommand {
                cla: 0x80,
                ins: 0x03,
                p1: 0x11,
                p2: 0,
                length: raw_change_path.len() as u8,
                data: raw_change_path.to_vec(),
            })?;

            let chunk = |base: SignP1, mut message: &[u8]| -> Result<_, Self::Err> {
                assert!(message.len() > 0, "initial message must be non-empty");
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
                }
            };

            debug!(
                "Nervos CKB Ledger app message {:02x?} with length {:?}",
                message,
                message.len()
            );

            let ctx_count = parse::split_off_at(&mut message, 2)?
                .read_u16::<BigEndian>()
                .unwrap();
            debug!("Nervos CKB Ledger hvave {:?} ctx tx", ctx_count);

            for _ in 0..ctx_count {
                let ctx_len = parse::split_off_at(&mut message, 2)?
                    .read_u16::<BigEndian>()
                    .unwrap();
                debug!("Nervos CKB Ledger ctx raw tx length {:?}", ctx_len);

                let ctx_tx = parse::split_off_at(&mut message, ctx_len as usize)?;
                debug!("Nervos CKB Ledger ctx raw tx {:?}", ctx_tx);
                debug!("Nervos CKB Ledger new raw tx {:?}", message);

                chunk(SignP1::NEXT | SignP1::IS_CONTEXT, ctx_tx.as_ref())?;
            }

            let response = chunk(SignP1::NEXT, message.as_ref())?;

            debug!(
                "Nervos CKB Ledger result is {:02x?} with length {:?}",
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
