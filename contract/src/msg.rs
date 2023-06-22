use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    AddKey {
        public_key: String,
        // only for testing really
        inject_privkey: Option<String>,
    },
    UpdateKeyOwner {
        owner_public_key: String,
        new_owner_public_key: String,
        hash_to_sign: String,
        hash_signed_by_public_key: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct CreatePresigResponse {
    result: Status,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Success,
    Error,
}

/// also possible to get the input with the x,y values rather than a 64 byte string
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// #[serde(rename_all = "snake_case")]
// pub struct PublicKey {
//     x: String,
//     y: String
// }

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Sign {
        user_public_key: String,
        hash_to_sign: String,
        hash_signed_by_public_key: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct SignResponse {
    pub(crate) signature: String,
}
