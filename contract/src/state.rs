use cosmwasm_std::{StdResult, Storage};
use cosmwasm_storage::{singleton, singleton_read};

pub fn save_key(storage: &mut dyn Storage, owner_pubkey: &[u8], key: Vec<u8>) -> StdResult<()> {
    let mut sg = singleton(storage, owner_pubkey);
    sg.save(&key)
}

pub fn may_load_key(storage: &dyn Storage, owner_pubkey: &[u8]) -> StdResult<Option<Vec<u8>>> {
    let sg = singleton_read(storage, owner_pubkey);
    match sg.load() {
        Ok(pk) => Ok(Some(pk)),
        Err(_) => Ok(None),
    }
}