//! Cosmos Account Generation
//!
//! - 타원곡선: secp256k1
//! - 해시: SHA-256 + RIPEMD-160 (HASH160)
//! - 주소 형식: Bech32 (cosmos1...)
//! - BIP-44 경로: m/44'/118'/0'/0/0
//!
//! ## 주소 생성 과정
//! 1. 시드 → BIP-32 마스터 키
//! 2. 경로 m/44'/118'/0'/0/0 도출
//! 3. 개인키 → secp256k1 압축 공개키 (33바이트)
//! 4. 공개키 → HASH160 (20바이트)
//! 5. Bech32 인코딩 (hrp = "cosmos")
//!
//! ## 다른 Cosmos SDK 체인들
//! - Cosmos Hub: cosmos1...
//! - Osmosis: osmo1...
//! - Juno: juno1...
//! - Terra: terra1...
//! - Injective: inj1...

use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, SecretKey, PublicKey};

use crate::bip32::{master_key_from_seed, ExtendedPrivateKey};
use crate::bip39::mnemonic_to_seed;
use crate::utils::bech32::encode_bech32;

/// Cosmos 계정
#[derive(Debug, Clone)]
pub struct CosmosAccount {
    /// 개인키 (32바이트)
    pub private_key: [u8; 32],
    /// 압축 공개키 (33바이트)
    pub public_key: [u8; 33],
    /// 공개키 해시 (20바이트) - HASH160(pubkey)
    pub pubkey_hash: [u8; 20],
}

/// Cosmos Hub 기본 도출 경로
pub const COSMOS_PATH: &str = "m/44'/118'/0'/0/0";

/// Cosmos SDK 체인 HRP (Human Readable Part)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CosmosChain {
    /// Cosmos Hub (cosmos1...)
    CosmosHub,
    /// Osmosis (osmo1...)
    Osmosis,
    /// Juno (juno1...)
    Juno,
    /// Terra (terra1...)
    Terra,
    /// Injective (inj1...)
    Injective,
    /// Secret Network (secret1...)
    Secret,
    /// Akash (akash1...)
    Akash,
    /// Kava (kava1...)
    Kava,
}

impl CosmosChain {
    /// 체인의 Bech32 HRP 반환
    pub fn hrp(&self) -> &'static str {
        match self {
            CosmosChain::CosmosHub => "cosmos",
            CosmosChain::Osmosis => "osmo",
            CosmosChain::Juno => "juno",
            CosmosChain::Terra => "terra",
            CosmosChain::Injective => "inj",
            CosmosChain::Secret => "secret",
            CosmosChain::Akash => "akash",
            CosmosChain::Kava => "kava",
        }
    }

    /// 체인의 BIP-44 coin type 반환
    pub fn coin_type(&self) -> u32 {
        match self {
            CosmosChain::CosmosHub => 118,
            CosmosChain::Osmosis => 118,     // Cosmos Hub와 동일
            CosmosChain::Juno => 118,        // Cosmos Hub와 동일
            CosmosChain::Terra => 330,
            CosmosChain::Injective => 60,    // EVM 호환
            CosmosChain::Secret => 529,
            CosmosChain::Akash => 118,
            CosmosChain::Kava => 459,
        }
    }
}

impl CosmosAccount {
    /// 개인키에서 Cosmos 계정 생성
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let public_key = private_key_to_public_key(&private_key);
        let pubkey_hash = hash160(&public_key);

        CosmosAccount {
            private_key,
            public_key,
            pubkey_hash,
        }
    }

    /// 확장 개인키에서 Cosmos 계정 생성
    pub fn from_extended_key(extended_key: &ExtendedPrivateKey) -> Self {
        Self::from_private_key(extended_key.private_key)
    }

    /// 시드에서 Cosmos 계정 생성 (기본 경로)
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        Self::from_seed_with_path(seed, COSMOS_PATH)
    }

    /// 시드에서 특정 경로로 Cosmos 계정 생성
    pub fn from_seed_with_path(seed: &[u8], path: &str) -> Result<Self, String> {
        let master = master_key_from_seed(seed)?;
        let derived = master.derive_path(path)?;
        Ok(Self::from_extended_key(&derived))
    }

    /// 니모닉에서 Cosmos 계정 생성
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, String> {
        let seed = mnemonic_to_seed(mnemonic, passphrase);
        Self::from_seed(&seed)
    }

    /// 니모닉에서 특정 체인의 Cosmos 계정 생성
    pub fn from_mnemonic_for_chain(
        mnemonic: &str,
        passphrase: &str,
        chain: CosmosChain
    ) -> Result<Self, String> {
        let seed = mnemonic_to_seed(mnemonic, passphrase);
        let path = format!("m/44'/{}'/0'/0/0", chain.coin_type());
        Self::from_seed_with_path(&seed, &path)
    }

    // ═══════════════════════════════════════════════════════════════
    // 주소 생성 메서드
    // ═══════════════════════════════════════════════════════════════

    /// 특정 체인의 주소 반환 (Bech32)
    pub fn address_for_chain(&self, chain: CosmosChain) -> String {
        encode_bech32(chain.hrp(), None, &self.pubkey_hash)
    }

    /// Cosmos Hub 주소 반환 (cosmos1...)
    pub fn address(&self) -> String {
        self.address_for_chain(CosmosChain::CosmosHub)
    }

    /// 커스텀 HRP로 주소 반환
    pub fn address_with_hrp(&self, hrp: &str) -> String {
        encode_bech32(hrp, None, &self.pubkey_hash)
    }

    /// 개인키를 hex 문자열로 반환
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }

    /// 공개키를 hex 문자열로 반환
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// 공개키 해시를 hex 문자열로 반환
    pub fn pubkey_hash_hex(&self) -> String {
        hex::encode(self.pubkey_hash)
    }
}

// ═══════════════════════════════════════════════════════════════
// 내부 함수
// ═══════════════════════════════════════════════════════════════

/// 개인키 → 압축 공개키 (secp256k1)
fn private_key_to_public_key(private_key: &[u8; 32]) -> [u8; 33] {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(private_key).expect("유효한 개인키");
    let public = PublicKey::from_secret_key(&secp, &secret);
    public.serialize() // 압축 공개키 (33바이트)
}

/// HASH160 = RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(sha256_hash);

    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosmos_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let account = CosmosAccount::from_mnemonic(mnemonic, "").unwrap();

        println!("=== Cosmos Hub (m/44'/118'/0'/0/0) ===");
        println!("개인키: {}", account.private_key_hex());
        println!("공개키: {}", account.public_key_hex());
        println!("공개키 해시: {}", account.pubkey_hash_hex());
        println!("주소: {}", account.address());
    }

    #[test]
    fn test_cosmos_multiple_chains() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let account = CosmosAccount::from_mnemonic(mnemonic, "").unwrap();

        println!("\n=== 같은 키로 여러 체인 주소 ===\n");

        // 같은 공개키 해시로 다른 HRP의 주소 생성
        let chains = [
            CosmosChain::CosmosHub,
            CosmosChain::Osmosis,
            CosmosChain::Juno,
            CosmosChain::Akash,
            CosmosChain::Secret,
        ];

        for chain in chains {
            println!("{:?}: {}", chain, account.address_for_chain(chain));
        }
    }

    #[test]
    fn test_cosmos_different_coin_types() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        println!("\n=== 체인별 다른 coin type 사용 ===\n");

        // 각 체인의 고유 coin type으로 계정 생성
        let chains = [
            (CosmosChain::CosmosHub, "Cosmos Hub"),
            (CosmosChain::Terra, "Terra"),
            (CosmosChain::Injective, "Injective"),
            (CosmosChain::Secret, "Secret"),
            (CosmosChain::Kava, "Kava"),
        ];

        for (chain, name) in chains {
            let account = CosmosAccount::from_mnemonic_for_chain(mnemonic, "", chain).unwrap();
            let path = format!("m/44'/{}'/0'/0/0", chain.coin_type());
            println!("{} ({})", name, path);
            println!("주소: {}", account.address_for_chain(chain));
            println!();
        }
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");

        println!("\n=== Cosmos 계정 목록 (첫 5개) ===\n");

        for i in 0..5 {
            let path = format!("m/44'/118'/0'/0/{}", i);
            let account = CosmosAccount::from_seed_with_path(&seed, &path).unwrap();

            println!("경로: {}", path);
            println!("주소: {}", account.address());
            println!();
        }
    }

    #[test]
    fn test_hash160() {
        // 테스트 벡터: Bitcoin과 동일한 HASH160 사용
        let pubkey = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let hash = hash160(&pubkey);

        // Bitcoin과 동일한 결과
        assert_eq!(
            hex::encode(hash),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[test]
    fn test_bech32_encoding() {
        // HASH160 → Cosmos 주소 테스트
        let pubkey_hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let address = encode_bech32("cosmos", None, &pubkey_hash);

        // cosmos1... 형식 확인
        assert!(address.starts_with("cosmos1"));
        println!("Bech32 테스트: {}", address);
    }
}
