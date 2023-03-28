use crate::errors::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::{Config, CONFIG};
use cosmwasm_std::{entry_point, Binary, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
use paillier::{Add, BigInt, EncodedCiphertext, EncryptionKey, Mul, Paillier};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use scrt_sss::{ECPoint, ECScalar, Secp256k1Point, Secp256k1Scalar};

/// // On-chain
/// ```
/// func execute_keygen_tx(encrypted_user_signing_key, public_signing_key_user, enc_public_key):
///     chain_signing_key, public_signing_key_chain = ECDSA.Keygen();
///
///     public_signing_key = chain_signing_key * public_signing_key_user;
///     save_to_state(chain_signing_key, public_signing_key_chain, encrypted_user_signing_key, public_signing_key_user, enc_public_key, public_signing_key);
/// ```
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    match msg {
        InstantiateMsg::KeyGen {
            encrypted_user_signing_key,
            public_signing_key_user,
            enc_public_key,
        } => {
            let encrypted_user_signing_key: EncodedCiphertext<BigInt> =
                bincode2::deserialize(encrypted_user_signing_key.as_slice()).unwrap();
            let public_signing_key_user: Secp256k1Point =
                bincode2::deserialize(public_signing_key_user.as_slice()).unwrap();
            let enc_public_key: EncryptionKey =
                bincode2::deserialize(enc_public_key.as_slice()).unwrap();

            // chain_signing_key, public_signing_key_chain = ECDSA.Keygen();
            let (chain_signing_key, public_signing_key_chain) = ecdsa_keygen([1u8; 32]);

            // public_signing_key = chain_signing_key * public_signing_key_user;
            let public_signing_key = public_signing_key_user.clone() * chain_signing_key.clone();

            CONFIG.save(
                deps.storage,
                &Config {
                    chain_signing_key,
                    public_signing_key_chain,
                    encrypted_user_signing_key,
                    public_signing_key_user,
                    enc_public_key,
                    public_signing_key,
                },
            )?;
            Ok(Response::default())
        }
    }
}

/// ```
/// // On-chain
/// func execute_sign_tx(message_hash, public_instance_key_user, proof, commitment):
/// 	assert(verify_dlog_proof_and_commitment(public_instance_key_user, proof, commitment); // Just create a stub that returns true for now.
/// 	encrypted_user_signing_key= load_from_state("encrypted_user_signing_key");
/// 	chain_signing_key = load_from_state("chain_signing_key");
///
/// 	k_chain, public_instance_key_chain = ECDSA.Keygen();
/// 	public_instance_key = k_chain * public_instance_key_user;
/// 	r = public_instance_key.x; // Get x-coordinate of the point
///
/// 	k_chain_inverse = modular_inverse(k_chain, secp256k1.q);
/// 	encrypted_chain_sig = k_chain_inverse * r * chain_signing_key * encrypted_user_signing_key + k_chain_inverse * message_hash // This is the homomorphic encryption operation. This is a complicated formula so let me know if it's not clear. Also, TODO: add noise (p*q) later on..
///
/// 	return encrypted_chain_sig, public_instance_key_chain
/// ```
#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Sign {
            message_hash,
            public_instance_key_user,
            proof,
            commitment,
        } => {
            // assert(verify_dlog_proof_and_commitment(public_instance_key_user, proof, commitment); // Just create a stub that returns true for now.
            if !verify_dlog_proof_and_commitment(
                public_instance_key_user.clone(),
                proof,
                commitment,
            ) {
                return Err(ContractError::Std(StdError::generic_err(
                    "Unable to verify dlog proof and commitment",
                )));
            }

            let config = CONFIG.load(deps.storage)?;
            let enc_public_key = config.enc_public_key;
            let encrypted_user_signing_key = config.encrypted_user_signing_key;
            let chain_signing_key = config.chain_signing_key;

            // k_chain, public_instance_key_chain = ECDSA.Keygen();
            let (k_chain, public_instance_key_chain) = ecdsa_keygen([3u8; 32]);

            // public_instance_key = k_chain * public_instance_key_user;
            let public_instance_key = public_instance_key_user * k_chain.clone();

            // r = public_instance_key.x; // Get x-coordinate of the point
            let r = public_instance_key.x();

            // k_chain_inverse = modular_inverse(k_chain, secp256k1.q);
            let k_chain_inverse = k_chain.inv();

            // encrypted_chain_sig = k_chain_inverse * r * chain_signing_key * encrypted_user_signing_key + k_chain_inverse * message_hash // This is the homomorphic encryption operation. This is a complicated formula so let me know if it's not clear. Also, TODO: add noise (p*q) later on..

            let k_chain_inverse_mul_r_mul_chain_signing_key = BigInt::from_str_radix(
                &(k_chain_inverse.clone() * r * chain_signing_key).to_hex(),
                16,
            )
            .unwrap();
            let k_chain_inverse_mul_message_hash =
                BigInt::from_str_radix(&(k_chain_inverse * message_hash).to_hex(), 16).unwrap();

            let encrypted_chain_sig = Paillier::add(
                &enc_public_key,
                Paillier::mul(
                    &enc_public_key,
                    encrypted_user_signing_key,
                    k_chain_inverse_mul_r_mul_chain_signing_key,
                ),
                k_chain_inverse_mul_message_hash,
            );

            let encrypted_chain_sig: Binary =
                bincode2::serialize(&encrypted_chain_sig).unwrap().into();
            let public_instance_key_chain: Binary = bincode2::serialize(&public_instance_key_chain)
                .unwrap()
                .into();

            let result: Binary =
                bincode2::serialize(&(encrypted_chain_sig, public_instance_key_chain))
                    .unwrap()
                    .into();

            Ok(Response::default().set_data(result))
        }
    }
}

fn verify_dlog_proof_and_commitment(
    public_instance_key_user: Secp256k1Point,
    proof: Binary,
    commitment: Binary,
) -> bool {
    true
}

fn ecdsa_keygen(seed: [u8; 32]) -> (Secp256k1Scalar, Secp256k1Point) {
    let mut rng = ChaChaRng::from_seed(seed); // rng::thread_rng();
    let privkey = Secp256k1Scalar::random(&mut rng);
    let pubkey = Secp256k1Point::generate(&privkey);

    (privkey, pubkey)
}
#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Binary,
    };
    use paillier::{Decrypt, DecryptionKey, Encrypt, KeyGeneration, Paillier};

    /// ```
    /// // User
    /// func keygen_user():
    ///     user_signing_key, public_signing_key_user = ECDSA.Keygen();
    ///     enc_secret_key, enc_public_key = Paillier.Keygen();
    ///
    ///     encrypted_user_signing_key = Paillier.encrypt(enc_secret_key, user_signing_key);
    ///
    ///     send_keygen_tx(encrypted_user_signing_key, public_signing_key_user, enc_public_key);
    ///
    ///     Save ( (user_signing_key, public_signing_key_user), (enc_secret_key, enc_public_key) ); // need to keep these keys for later
    /// ```
    fn keygen_user() -> (
        (Secp256k1Scalar, Secp256k1Point),
        (DecryptionKey, EncryptionKey),
        EncodedCiphertext<BigInt>,
    ) {
        // user_signing_key, public_signing_key_user = ECDSA.Keygen();
        let (user_signing_key, public_signing_key_user) = ecdsa_keygen([0u8; 32]);

        // enc_secret_key, enc_public_key = Paillier.Keygen();
        let (enc_public_key, enc_secret_key) = Paillier::keypair().keys(); // Also ChaChaRng::from_seed([0u8; 32]) behind the scenes

        // encrypted_user_signing_key = Paillier.encrypt(enc_secret_key, user_signing_key);
        let encrypted_user_signing_key: EncodedCiphertext<BigInt> = Paillier::encrypt(
            &enc_public_key,
            BigInt::from_str_radix(&user_signing_key.to_hex(), 16).unwrap(),
        );

        (
            (user_signing_key, public_signing_key_user),
            (enc_secret_key, enc_public_key),
            encrypted_user_signing_key,
        )
    }

    ///```
    /// // User
    /// func generate_sign_tx(enc_secret_key, message_hash):
    ///     k_user, public_instance_key_user = ECDSA.Keygen();
    ///     proof, commitment = generate_dlog_proof_and_commit(k_user, public_instance_key_user); // Just create a stub that returns whatever, don't implement
    ///    
    ///     // Send a tx with all the data to the chain. Get encrypted_chain_sig back
    ///     encrypted_chain_sig, public_instance_key_chain = send_sign_tx(message_hash, public_instance_key_user, proof, commitment);
    ///    
    ///     public_instance_key = k_user * public_instance_key_chain;
    ///     r = public_instance_key.x; // Get x-coordinate of the point
    ///    
    ///     chain_sig = Paillier.decrypt(enc_secret_key, encrypted_chain_sig);
    ///     s = (modular_inverse(k_user, secp256k1.q) * chain_sig) % secp256k1.q;
    ///    
    ///     signature = (r, s)
    ///     return signature;
    ///  ```
    fn generate_sign_tx(
        enc_secret_key: &DecryptionKey,
        message_hash: Secp256k1Scalar,
    ) -> (Secp256k1Scalar, Secp256k1Point, Binary, Binary) {
        // k_user, public_instance_key_user = ECDSA.Keygen();
        let (k_user, public_instance_key_user) = ecdsa_keygen([2u8; 32]);

        // proof, commitment = generate_dlog_proof_and_commit(k_user, public_instance_key_user); // Just create a stub that returns whatever, don't implement
        let (proof, commitment) =
            generate_dlog_proof_and_commit(k_user.clone(), public_instance_key_user.clone());

        (k_user, public_instance_key_user, proof, commitment)
    }

    fn generate_dlog_proof_and_commit(
        _k_user: Secp256k1Scalar,
        _public_instance_key_user: Secp256k1Point,
    ) -> (Binary, Binary) {
        (Binary::from(vec![]), Binary::from(vec![]))
    }

    #[test]
    fn test() {
        let (
            (user_signing_key, public_signing_key_user),
            (enc_secret_key, enc_public_key),
            encrypted_user_signing_key,
        ) = keygen_user();

        let mut deps = mock_dependencies();

        let encrypted_user_signing_key: Binary = bincode2::serialize(&encrypted_user_signing_key)
            .unwrap()
            .into();
        let public_signing_key_user: Binary = bincode2::serialize(&public_signing_key_user)
            .unwrap()
            .into();
        let enc_public_key: Binary = bincode2::serialize(&enc_public_key).unwrap().into();

        // send encryption_key to the contract
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("yolo", &[]),
            InstantiateMsg::KeyGen {
                encrypted_user_signing_key,
                public_signing_key_user,
                enc_public_key,
            },
        )
        .unwrap();

        let message_hash = Secp256k1Scalar::from_slice(&[17u8; 32]).unwrap();

        let (k_user, public_instance_key_user, proof, commitment) =
            generate_sign_tx(&enc_secret_key, message_hash.clone());

        let result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("yolo", &[]),
            ExecuteMsg::Sign {
                message_hash,
                public_instance_key_user,
                proof,
                commitment,
            },
        )
        .unwrap()
        .data
        .unwrap();

        let (encrypted_chain_sig, public_instance_key_chain): (Binary, Binary) =
            bincode2::deserialize(result.as_slice()).unwrap();
        let encrypted_chain_sig: EncodedCiphertext<BigInt> =
            bincode2::deserialize(encrypted_chain_sig.as_slice()).unwrap();
        let public_instance_key_chain: Secp256k1Point =
            bincode2::deserialize(public_instance_key_chain.as_slice()).unwrap();

        // public_instance_key = k_user * public_instance_key_chain;
        let public_instance_key = public_instance_key_chain * k_user.clone();

        // r = public_instance_key.x; // Get x-coordinate of the point
        let r = public_instance_key.x();

        // chain_sig = Paillier.decrypt(enc_secret_key, encrypted_chain_sig);
        let chain_sig = Paillier::decrypt(&enc_secret_key, encrypted_chain_sig);

        // s = (modular_inverse(k_user, secp256k1.q) * chain_sig) % secp256k1.q;
        let s =
            k_user.inv() * Secp256k1Scalar::from_str(&chain_sig.to_str_radix(16, false)).unwrap();

        // signature = (r, s)
        let signature = (r, s);
    }
}
