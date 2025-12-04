use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultBlob {
    pub version: u32,
    pub salt: Vec<u8>,
    pub params: String, // argon2 参数序列化，例如 "m=19456,t=2,p=1"
    pub hash: Vec<u8>,
}

pub fn create_vault(password: &str) -> anyhow::Result<Vec<u8>>; // -> dpapi_encrypted_blob
pub fn load_vault(dpapi_blob: &[u8]) -> anyhow::Result<VaultBlob>;
pub fn verify_password(dpapi_blob: &[u8], password: &str) -> anyhow::Result<bool>;
