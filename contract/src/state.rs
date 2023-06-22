use cw_storage_plus::Map;

// map pubkey, which has signing rights,
// to mathematically unassociated private key which signs
pub const STATE: Map<&[u8], Vec<u8>> = Map::new("state");
