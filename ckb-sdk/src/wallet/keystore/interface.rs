use std::alloc::GlobalAlloc;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use bitcoin_hashes::{hash160, Hash};
use dyn_clone::{self, DynClone};
use either::Either;
use failure::Fail;
use secp256k1::recovery::RecoverableSignature;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use void::Void;

use crate::key_adapter::KeyAdapter;
use crate::signing::{FullyAbstractSingleShotSigner, SignPrehashedHelper, SignerSingleShot};
use crate::tx_helper::SignerFnTrait;
use crate::wallet::bip32::{
    ChainCode, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint,
};

use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_types::{core::TransactionView, packed::Byte32};
use ckb_types::{H160, H256};

use super::ScryptType;

/// Trait for a key store, i.e. a source of independent signing keys which can be
/// extended.
pub trait AbstractKeyStore: Sized {
    const SOURCE_NAME: &'static str;

    /// Error type for key store operations.
    type Err;

    /// Identifier for the individual accounts, i.e. those which per idiomatic
    /// use of UTXO are not reused between transactions for sake of the actors'
    /// privacy.
    ///
    /// This must always contain at least the a `H160` hash as mandated by the
    /// blockchain. It may also contain more information to different between
    /// underlying keystores, e.g. files vs hardware wallets.
    type AccountId;

    /// Abstract or concrete master private key
    type AccountCap: AbstractMasterPrivKey;

    // Just box it because no `impl Trait` in traits for now
    fn list_accounts(&mut self) -> Result<Box<dyn Iterator<Item = Self::AccountId>>, Self::Err>;

    fn from_dir(dir: PathBuf, scrypt_type: ScryptType) -> Result<Self, Self::Err>;

    fn borrow_account<'a, 'b>(
        &'a mut self,
        account_id: &'b Self::AccountId,
    ) -> Result<&'a Self::AccountCap, Self::Err>;
}

/// Capability for deriving (perhaps abstract) signing keys
/// derived key pairs and sign messages.
///
/// For a software key store, would probably be the actual private key, but
/// for a hardware wallet would be merely the capability to communicate with
/// that wallet assuming a derivation path.
pub trait AbstractMasterPrivKey: DynClone {
    /// Error type for operations.
    type Err;

    /// Abstract or concrete derived private key
    type Privkey: AbstractPrivKey<Err = Self::Err>;

    fn extended_privkey(&self, path: &[ChildNumber]) -> Result<Self::Privkey, Self::Err>;

    fn extended_pubkey(&self, path: &[ChildNumber]) -> Result<ExtendedPubKey, Self::Err> {
        let public_key = self.extended_privkey(path)?.public_key()?;
        Ok(ExtendedPubKey {
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
            chain_code: ChainCode([0; 32]), // dummy, unused
        })
    }

    fn derived_pubkey_hash(&self, path: &[ChildNumber]) -> Result<H160, Self::Err> {
        let extended_public_key = self.extended_pubkey(path)?;
        Ok(hash_publick_key(&extended_public_key.public_key))
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
            let pubkey_hash = self
                .derived_pubkey_hash(path.as_ref())
                .map_err(Either::Left)?;
            external_key_set.push((path, pubkey_hash.clone()));
        }

        let mut change_key_set = Vec::new();
        for i in 0..change_max_len {
            let path_string = format!("m/44'/309'/0'/{}/{}", KeyChain::Change as u8, i);
            let path = DerivationPath::from_str(path_string.as_str()).unwrap();
            let pubkey_hash = self
                .derived_pubkey_hash(path.as_ref())
                .map_err(Either::Left)?;
            change_key_set.push((path, pubkey_hash.clone()));
            if change_last == &pubkey_hash {
                return Ok(DerivedKeySet {
                    external: external_key_set,
                    change: change_key_set,
                });
            }
        }
        Err(Either::Right(SearchDerivedAddrFailed))
    }

    fn hash_transaction(&self, tx_view: TransactionView) -> Byte32 {
        tx_view.hash()
    }
}

dyn_clone::clone_trait_object!(<'a> AbstractMasterPrivKey<Privkey = FullyBoxedAbstractPrivkey<'a>, Err = String>);

pub type FullyBoxedAbstractMasterPrivkey<'a> =
    Box<dyn AbstractMasterPrivKey<Privkey = FullyBoxedAbstractPrivkey<'a>, Err = String> + 'a>;

impl<K: ?Sized + AbstractMasterPrivKey> AbstractMasterPrivKey for Box<K>
where
    Box<K>: Clone,
{
    type Err = K::Err;

    type Privkey = K::Privkey;

    fn extended_privkey(&self, path: &[ChildNumber]) -> Result<Self::Privkey, Self::Err> {
        (&**self).extended_privkey(path)
    }

    fn extended_pubkey(&self, path: &[ChildNumber]) -> Result<ExtendedPubKey, Self::Err> {
        (&**self).extended_pubkey(path)
    }

    fn hash_transaction(&self, tx_view: TransactionView) -> Byte32 {
        (&**self).hash_transaction(tx_view)
    }
}

pub struct MasterPrivKeySigner<Key: ?Sized> {
    path_map: HashMap<H160, DerivationPath>,
    private_key: Key,
}

// https://GitHub.com/dtolnay/dyn-clone/issues/1 to make better
impl<T: ?Sized + DynClone> DynClone for MasterPrivKeySigner<T> {
    unsafe fn clone_box(&self) -> *mut () {
        let box_tail = dyn_clone::clone_box(&self.private_key);
        let layout = std::alloc::Layout::for_value(self);
        let ptr = std::alloc::System.alloc(layout) as *mut Self;
        let path_map = self.path_map.clone();
        std::ptr::write(&mut (*ptr).path_map, path_map);
        std::ptr::copy_nonoverlapping::<u8>(
            &mut (*ptr).private_key as *mut _,
            &mut *box_tail as *mut _,
            std::mem::size_of_val(&*box_tail),
        );
        let raw_tail = Box::into_raw(box_tail);
        std::alloc::System.dealloc(std::alloc::Layout::for_value(&self.private_key), raw_tail);
        ptr
    }
}

impl<Key> SignerFnTrait for MasterPrivKeySigner<Key>
where
    //Box<Self>: Clone,
    Key: ?Sized + AbstractMasterPrivKey<Err = String>,
    Key::Privkey: AbstractPrivKey<Err = String>,
    <Key::Privkey as AbstractPrivKey>::SingleShot: SignerSingleShot<Err = String>,
{
    type SingleShot = FullyAbstractSingleShotSigner<'static>;

    fn new_signature_builder(
        &mut self,
        lock_args: &HashSet<H160>,
    ) -> Result<Option<Self::SingleShot>, String> {
        let path = match lock_args
            .iter()
            .find_map(|lock_arg| self.path_map.get(lock_arg))
        {
            None => return Ok(None),
            Some(path) => path.clone(),
        };
        let derived_key = KeyAdapter(self.0)
            .extended_privkey(path.as_ref())
            .map_err(|err| err.to_string())?;
        PrivKeySigner(derived_key).new_signature_builder(lock_args)
    }
}

/// Trait for signing
pub trait AbstractPrivKey: DynClone {
    /// Error type for operations.
    type Err;

    type SingleShot: SignerSingleShot<Err = Self::Err>;

    /// Get the corresponding public key
    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err>;

    // TODO make this not take a hash
    fn sign(&self, message: &H256) -> Result<secp256k1::Signature, Self::Err>;

    fn begin_sign_recoverable(&self) -> Self::SingleShot;
}

dyn_clone::clone_trait_object!(<'a> AbstractPrivKey<SingleShot = FullyAbstractSingleShotSigner<'a>, Err = String>);

pub type FullyBoxedAbstractPrivkey<'a> =
    Box<dyn AbstractPrivKey<SingleShot = FullyAbstractSingleShotSigner<'a>, Err = String> + 'a>;

impl<K: ?Sized + AbstractPrivKey> AbstractPrivKey for Box<K>
where
    Box<K>: Clone,
{
    type Err = K::Err;

    type SingleShot = K::SingleShot;

    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        (&**self).public_key()
    }

    fn sign(&self, message: &H256) -> Result<secp256k1::Signature, Self::Err> {
        (&**self).sign(message)
    }

    fn begin_sign_recoverable(&self) -> Self::SingleShot {
        (&**self).begin_sign_recoverable()
    }
}

impl<K: ?Sized + AbstractPrivKey> AbstractPrivKey for &K {
    type Err = K::Err;

    type SingleShot = K::SingleShot;

    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        (*self).public_key()
    }

    fn sign(&self, message: &H256) -> Result<secp256k1::Signature, Self::Err> {
        (*self).sign(message)
    }

    fn begin_sign_recoverable(&self) -> Self::SingleShot {
        (*self).begin_sign_recoverable()
    }
}

// Only not using impl trait because unstable
type ExtendedPublicKeySignClosure<'a> =
    Box<dyn FnOnce(H256) -> Result<RecoverableSignature, Void> + 'a>;

impl AbstractPrivKey for ExtendedPrivKey {
    type Err = Void;

    type SingleShot = SignPrehashedHelper<ExtendedPublicKeySignClosure<'static>>;

    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        Ok(ExtendedPubKey::from_private(&SECP256K1, self).public_key)
    }

    fn sign(&self, message: &H256) -> Result<secp256k1::Signature, Void> {
        let message =
            secp256k1::Message::from_slice(message.as_bytes()).expect("Convert to message failed");
        Ok(SECP256K1.sign(&message, &self.private_key))
    }

    fn begin_sign_recoverable(&self) -> Self::SingleShot {
        let cloned_key = self.private_key.clone();
        SignPrehashedHelper::new(Box::new(move |message: H256| {
            let message = secp256k1::Message::from_slice(message.as_bytes())
                .expect("Convert to message failed");
            Ok(SECP256K1.sign_recoverable(&message, &cloned_key))
        }))
    }
}

pub struct PrivKeySigner<Key: ?Sized>(pub Key);

impl<T: ?Sized + DynClone> DynClone for PrivKeySigner<T> {
    unsafe fn clone_box(&self) -> *mut () {
        Box::into_raw(dyn_clone::clone_box(&self.0)) as *mut _
    }
}

impl<Key> SignerFnTrait for PrivKeySigner<Key>
where
    Box<Self>: Clone,
    Key: ?Sized + AbstractPrivKey<Err = String>,
    Key::SingleShot: SignerSingleShot<Err = String>,
{
    type SingleShot = Key::SingleShot;

    fn new_signature_builder(
        &mut self,
        lock_args: &HashSet<H160>,
    ) -> Result<Option<Self::SingleShot>, String> {
        let pubkey = self.0.public_key()?;
        let public_key_hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        Ok(if !lock_args.contains(&self.public_key_hash) {
            None
        } else {
            Some(KeyAdapter(self.private_key.begin_sign_recoverable()))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum KeyChain {
    External = 0,
    Change = 1,
}

pub struct DerivedKeySet {
    pub external: Vec<(DerivationPath, H160)>,
    pub change: Vec<(DerivationPath, H160)>,
}

impl DerivedKeySet {
    pub fn get_path(&self, hash160: &H160) -> Option<(KeyChain, DerivationPath)> {
        for (path, pubkey_hash) in &self.external {
            if pubkey_hash == hash160 {
                return Some((KeyChain::External, path.clone()));
            }
        }
        for (path, pubkey_hash) in &self.change {
            if pubkey_hash == hash160 {
                return Some((KeyChain::Change, path.clone()));
            }
        }
        None
    }
}

#[derive(Debug, Fail, Eq, PartialEq)]
#[fail(display = "Search derived address failed")]
pub struct SearchDerivedAddrFailed;

pub fn hash_publick_key(public_key: &secp256k1::PublicKey) -> H160 {
    H160::from_slice(&blake2b_256(&public_key.serialize()[..])[0..20])
        .expect("Generate hash(H160) from pubkey failed")
}

pub const MANDATORY_PREFIX: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 44 },
    ChildNumber::Hardened { index: 309 },
    ChildNumber::Hardened { index: 0 },
];

pub fn is_valid_derivation_path(path: &[ChildNumber]) -> bool {
    path.iter()
        .map(Some)
        .chain(std::iter::repeat(None))
        .zip(MANDATORY_PREFIX.iter())
        .all(|(x, y)| x == Some(y))
}
