use crate::errors::CustomContractError;
use cosmwasm_std::{
    ensure, entry_point, to_binary, Binary, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult, Deps, Api,
};

use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;

use tiny_keccak::{Keccak as keccak256, Hasher};
use crate::rng::Prng;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, SignResponse};
use crate::state::{save_key, may_load_key};

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    Ok(Response::default())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, CustomContractError> {
    match msg {
        ExecuteMsg::AddKey {
            public_key,
            inject_privkey,
        } => add_key(deps, env, info, public_key, inject_privkey),
        ExecuteMsg::UpdateKeyOwner {
            owner_public_key,
            new_owner_public_key,
            hash_to_sign,
            hash_signed_by_public_key,
        } => update_key_owner(
            deps,
            env,
            info,
            owner_public_key,
            new_owner_public_key,
            hash_to_sign,
            hash_signed_by_public_key,
        ),
    }
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Sign {
            user_public_key,
            hash_to_sign,
            hash_signed_by_public_key,
        } => Ok(to_binary(&query_sign(
            deps,
            env,
            user_public_key,
            hash_to_sign,
            hash_signed_by_public_key,
        )?)?),
    }
}

fn update_key_owner(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    owner_public_key: String,
    new_owner_public_key: String,
    hash_to_sign: String,
    hash_signed_by_public_key: String,
) -> Result<Response, CustomContractError> {
    let pk = may_load_key(deps.storage, owner_public_key.as_bytes())?;
    match pk {
        None => Err(CustomContractError::Std(StdError::generic_err(format!(
            "Key not found: {}",
            owner_public_key
        )))),
        Some(pk) => {
            verify_signature(deps.api, hash_to_sign, hash_signed_by_public_key, owner_public_key)?;
            save_key(
                deps.storage,
                new_owner_public_key.as_bytes(),
                hex::decode(pk).unwrap(),
            )?;
            Ok(Response::default())
        }
    }
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = keccak256::v256();
    hasher.update(bytes);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    hash
}

fn add_key(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    user_public_key: String,
    inject_privkey: Option<String>,
) -> Result<Response, CustomContractError> {
    let pk = may_load_key(deps.storage, user_public_key.as_bytes())?;
    match pk {
        Some(_) => Err(CustomContractError::Std(StdError::generic_err(format!(
            "Key already added: {}",
            user_public_key
        )))),
        None => match inject_privkey {
            None => {
                let mut rng = Prng::new(b"hello", &[]);
                let pk_bytes = &mut rng.rand_bytes();
                
                let full_pubkey_bytes = full_pubkey_from_pk(pk_bytes.to_vec())?;
                let full_pubkey = hex::encode(full_pubkey_bytes.clone());
                println!("PUBKEY is {}", full_pubkey);
                let eth_hash: [u8; 32] = keccak256(&full_pubkey_bytes[1..]);
                println!("ETH HASH is {}", hex::encode(&eth_hash));
                let eth_address = format!("0x{}", hex::encode(&eth_hash[eth_hash.len() - 20..]));
                save_key(
                    deps.storage,
                    &hex::decode(user_public_key)
                    .map_err(|e| CustomContractError::Std(StdError::generic_err(e.to_string())))?,
                    pk_bytes.to_vec(),
                )?;
                Ok(Response::new()
                    .add_attribute_plaintext("pubkey", full_pubkey)
                    .add_attribute_plaintext("eth_address", eth_address)
                )
            }
            Some(pk) => {
                let pk_bytes = hex::decode(pk)
                .map_err(|e| CustomContractError::Std(StdError::generic_err(e.to_string())))?;
            
                let full_pubkey_bytes = full_pubkey_from_pk(pk_bytes.clone())?;
                let full_pubkey = hex::encode(full_pubkey_bytes.clone());
                println!("PUBKEY is {}", full_pubkey);
                let eth_hash: [u8; 32] = keccak256(&full_pubkey_bytes[1..]);
                println!("ETH HASH is {}", hex::encode(&eth_hash));
                let eth_address = format!("0x{}", hex::encode(&eth_hash[eth_hash.len() - 20..]));
                save_key(
                    deps.storage,
                    &hex::decode(user_public_key)
                    .map_err(|e| CustomContractError::Std(StdError::generic_err(e.to_string())))?,
                    pk_bytes,
                )?;
                Ok(Response::new()
                    .add_attribute_plaintext("pubkey", full_pubkey)
                    .add_attribute_plaintext("eth_address", eth_address)
                )
            }
        },
    }
}

fn full_pubkey_from_pk(pk_bytes: Vec<u8>) -> StdResult<Vec<u8>> {
    
    let signing_key = SigningKey::from_bytes(pk_bytes.as_slice().into())
        .expect("Failed to create signing key");

    let verifying_key = k256::ecdsa::VerifyingKey::from(&signing_key);
    // let pubkey_bytes = EncodedPoint::from(&verifying_key).as_bytes().to_vec();
    // let compressed_pubkey = hex::encode(pubkey_bytes.clone());
    let pubkey_key: PublicKey = PublicKey::from(&verifying_key);
    let public_key_bytes: Vec<u8> = pubkey_key.to_encoded_point(false).as_ref().to_vec();
    Ok(public_key_bytes)
}

fn query_sign(
    deps: Deps,
    _env: Env,
    user_public_key: String,
    hash_to_sign: String,
    hash_signed_by_public_key: String,
) -> StdResult<SignResponse> {
    ensure!(
        verify_signature(
            deps.api,
            hash_to_sign.clone(),
            hash_signed_by_public_key,
            user_public_key.clone()
        )?,
        StdError::generic_err("Unauthorized: signature verification failed")
    );
    let pk = may_load_key(deps.storage, &hex::decode(user_public_key.clone())
    .map_err(|e| StdError::generic_err(e.to_string()))?)?;
    match pk {
        None => Err(StdError::generic_err(format!(
            "User not found: {}",
            user_public_key
        ))),
        Some(privkey) => {
            let signature = sig_string_from_hash(deps.api, hash_to_sign, privkey)?;
            Ok(SignResponse { signature })
        }
    }
}

fn verify_signature(api: &dyn Api, message: String, signature: String, pubkey: String) -> StdResult<bool> {
    Ok(api.secp256k1_verify(
        &hash_message(&message_from_string(message)),
        &hex::decode(signature).map_err(|e| StdError::generic_err(e.to_string()))?,
        &hex::decode(pubkey).map_err(|e| StdError::generic_err(e.to_string()))?,
    )?)
}

fn message_from_string(message: String) -> Vec<u8> {
    hex::decode(message).unwrap()
}

fn sig_string_from_hash(api: &dyn Api, hash: String, privkey: Vec<u8>) -> StdResult<String> {
    let msg = message_from_string(hash);
    let sig = api.secp256k1_sign(
        &hash_message(&msg),
        &privkey,
    ).map_err(|e| StdError::generic_err(e.to_string()))?;
    Ok(hex::encode(sig))
}

fn hash_message(message: &[u8]) -> [u8; 32] {
    const PREFIX: &str = "\x19Ethereum Signed Message:\n";

    let len = message.len();
    let len_string = len.to_string();

    let mut eth_message = Vec::with_capacity(PREFIX.len() + len_string.len() + len);
    eth_message.extend_from_slice(PREFIX.as_bytes());
    eth_message.extend_from_slice(len_string.as_bytes());
    eth_message.extend_from_slice(&message);

    keccak256(&eth_message)
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};

    fn instantiate_contract(deps: DepsMut) -> MessageInfo {
        let msg = InstantiateMsg {};
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps, mock_env(), info.clone(), msg).unwrap();
        info
    }

    #[test]
    // #[cfg(feature = "rand-std")]
    fn add_and_sign_with_key() {
        let mut deps = mock_dependencies();
        const PRIVKEY: &str = "6b6582a06ab08f38223a1e3b12ee8fc8a19efe690fb471dc151bb64588b23d96";
        const PUBKEY: &str = "040ea90e713bcb02581cd510611857770cb91b64969582b0943e3e7a5550b84856baa906964dca107a4401d325bd571faeca4270d22390f799a9cfb79e7456e458";
        // privkey 6b6582a06ab08f38223a1e3b12ee8fc8a19efe690fb471dc151bb64588b23d96
        // pubkey 040ea90e713bcb02581cd510611857770cb91b64969582b0943e3e7a5550b84856baa906964dca107a4401d325bd571faeca4270d22390f799a9cfb79e7456e458
        // => address 0xc1D4F3dcc31d86A66de90c3C5986f0666cc52ce4

        let info = instantiate_contract(deps.as_mut());
        // matching for convenience
        let msg = ExecuteMsg::AddKey {
            public_key: PUBKEY.to_string(),
            inject_privkey: Some(PRIVKEY.to_string()),
        };
        let res: Response = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        println!("Response: {:#?}", res);

        // add a random generated key too
        let msg = ExecuteMsg::AddKey {
            public_key: "040ea90e713bcb02581de510611857770cb91b64969582b0943e3e7a5550b84856baa906964dca107a4401d325bd571faeca4270d22390f799a9cfb79e7456e458".to_string(),
            inject_privkey: None,
        };
        let res: Response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        println!("Response: {:#?}", res);

        let query_msg = QueryMsg::Sign {
            user_public_key: PUBKEY.to_string(),
            hash_to_sign: "8f9eb4d768e5a44e35d52de66a3a0bc72d790e08cb8062536744a242ef4b6369".to_string(),
            hash_signed_by_public_key: "d03e39ff3c8f0d4ba23e37ce0d2ce3a8b2ad6d549026baed3c05f5925db43da23228129d141c9f2f0a501fae661467042bfe6593f535a17da4484b7a3dfea6dd".to_string(),
        };
        let query_res: SignResponse =
            from_binary(&query(deps.as_ref(), mock_env(), query_msg).unwrap()).unwrap();
        println!("Query response: {:#?}", query_res);
    }
}
