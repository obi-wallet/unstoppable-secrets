use crate::errors::CustomContractError;
use cosmwasm_std::{
    ensure, entry_point, to_binary, Binary, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult,
};

use libsecp256k1::{Message, SecretKey};
use libsecp256k1::{RecoveryId, Signature};

use web3::signing::keccak256;

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, SignResponse};
use crate::rng::Prng;
use crate::state::STATE;

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
pub fn query(deps: DepsMut, env: Env, msg: QueryMsg) -> StdResult<Binary> {
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
    let _state = STATE.load(deps.storage, owner_public_key.as_bytes())?;
    let state = STATE.may_load(deps.storage, owner_public_key.as_bytes())?;
    match state {
        None => Err(CustomContractError::Std(StdError::generic_err(format!(
            "Key not found: {}",
            owner_public_key
        )))),
        Some(pk) => {
            verify_signature(hash_to_sign, hash_signed_by_public_key, owner_public_key)?;
            STATE.save(
                deps.storage,
                new_owner_public_key.as_bytes(),
                &hex::decode(pk).unwrap(),
            )?;
            Ok(Response::default())
        }
    }
}

fn add_key(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    user_public_key: String,
    inject_privkey: Option<String>,
) -> Result<Response, CustomContractError> {
    let state = STATE.may_load(deps.storage, user_public_key.as_bytes())?;
    match state {
        Some(_) => Err(CustomContractError::Std(StdError::generic_err(format!(
            "Key already added: {}",
            user_public_key
        )))),
        None => match inject_privkey {
            None => {
                let mut rng = Prng::new(b"hello", &[]);
                let bytes = &mut rng.rand_bytes();
                let chain_private_key =
                    libsecp256k1::SecretKey::parse_slice(bytes).map_err(|_e| {
                        CustomContractError::Std(StdError::generic_err(
                            "Unable to create private key",
                        ))
                    })?;
                STATE.save(deps.storage, user_public_key.as_bytes(), &bytes.to_vec())?;
                Ok(Response::new().add_attribute_plaintext(
                    "pubkey",
                    format!(
                        "{:?}",
                        libsecp256k1::PublicKey::from_secret_key(&chain_private_key)
                    ),
                ))
            }
            Some(pk) => {
                let pubkey_bytes = libsecp256k1::PublicKey::from_secret_key(
                    &SecretKey::parse_slice(&hex::decode(pk.clone()).unwrap()).unwrap(),
                )
                .serialize();
                let pubkey = hex::encode(pubkey_bytes);
                let eth_hash: [u8; 32] = keccak256(&pubkey_bytes[1..]);
                let eth_address = format!("0x{}", hex::encode(&eth_hash[eth_hash.len() - 20..]));
                STATE.save(
                    deps.storage,
                    user_public_key.as_bytes(),
                    &hex::decode(pk).unwrap(),
                )?;
                Ok(Response::new()
                    .add_attribute_plaintext("pubkey", pubkey)
                    .add_attribute_plaintext("eth_address", eth_address))
            }
        },
    }
}

fn query_sign(
    deps: DepsMut,
    _env: Env,
    user_public_key: String,
    hash_to_sign: String,
    hash_signed_by_public_key: String,
) -> StdResult<SignResponse> {
    ensure!(
        verify_signature(
            hash_to_sign.clone(),
            hash_signed_by_public_key,
            user_public_key.clone()
        )?,
        StdError::generic_err("Unauthorized: signature verification failed")
    );
    let user_record = STATE.may_load(deps.storage, user_public_key.as_bytes())?;
    match user_record {
        None => Err(StdError::generic_err(format!(
            "User not found: {}",
            user_public_key
        ))),
        Some(privkey) => {
            let signature = sig_string_from_hash(hash_to_sign, privkey)?;
            Ok(SignResponse { signature })
        }
    }
}

fn verify_signature(message: String, signature: String, pubkey: String) -> StdResult<bool> {
    Ok(libsecp256k1::verify(
        &hash_message(message_from_string(message))?,
        &libsecp256k1::Signature::parse_standard_slice(
            &hex::decode(signature).map_err(|e| StdError::generic_err(e.to_string()))?,
        )
        .map_err(|e| StdError::generic_err(e.to_string()))?,
        &pubkey_from_string(pubkey),
    ))
}

fn pubkey_from_string(pubkey: String) -> libsecp256k1::PublicKey {
    libsecp256k1::PublicKey::parse_slice(&hex::decode(pubkey).unwrap(), None).unwrap()
}

fn message_from_string(message: String) -> libsecp256k1::Message {
    libsecp256k1::Message::parse_slice(&hex::decode(message).unwrap()).unwrap()
}

fn sig_string_from_hash(hash: String, privkey: Vec<u8>) -> StdResult<String> {
    let msg = message_from_string(hash);
    let sig: (Signature, RecoveryId) = libsecp256k1::sign(
        &hash_message(msg)?,
        &SecretKey::parse_slice(&privkey).unwrap(),
    );
    let mut sig_ser = sig.0.serialize().to_vec();
    sig_ser.push(sig.1.serialize());
    Ok(hex::encode(sig_ser))
}

fn hash_message(message: libsecp256k1::Message) -> StdResult<Message> {
    const PREFIX: &str = "\x19Ethereum Signed Message:\n";

    let message = message.serialize();
    let len = message.len();
    let len_string = len.to_string();

    let mut eth_message = Vec::with_capacity(PREFIX.len() + len_string.len() + len);
    eth_message.extend_from_slice(PREFIX.as_bytes());
    eth_message.extend_from_slice(len_string.as_bytes());
    eth_message.extend_from_slice(&message);

    Message::parse_slice(&keccak256(&eth_message)).map_err(|e| StdError::generic_err(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};
    #[allow(unused_imports)]
    use ethereum_types::H160;

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
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        println!("Response: {:#?}", res);

        let query_msg = QueryMsg::Sign {
            user_public_key: PUBKEY.to_string(),
            hash_to_sign: "8f9eb4d768e5a44e35d52de66a3a0bc72d790e08cb8062536744a242ef4b6369".to_string(),
            hash_signed_by_public_key: "d03e39ff3c8f0d4ba23e37ce0d2ce3a8b2ad6d549026baed3c05f5925db43da23228129d141c9f2f0a501fae661467042bfe6593f535a17da4484b7a3dfea6dd".to_string(),
        };
        let query_res: SignResponse =
            from_binary(&query(deps.as_mut(), mock_env(), query_msg).unwrap()).unwrap();
        println!("Query response: {:#?}", query_res);
    }
}
