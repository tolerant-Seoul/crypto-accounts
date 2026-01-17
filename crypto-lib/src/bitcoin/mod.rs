//! Bitcoin Account Generation
//!
//! - 타원곡선: secp256k1
//! - 해시: SHA-256 + RIPEMD-160 (HASH160)
//! - 주소 형식:
//!   - Legacy P2PKH: 1... (Base58Check)
//!   - SegWit P2WPKH: bc1... (Bech32)
//! - BIP-44 경로:
//!   - Legacy: m/44'/0'/0'/0/0
//!   - SegWit: m/84'/0'/0'/0/0
//!
//! ## 주소 생성 과정
//! 1. 개인키 → 공개키 (secp256k1, 압축)
//! 2. 공개키 → SHA-256 → RIPEMD-160 = 공개키 해시 (20바이트)
//! 3. Legacy: 버전(0x00) + 해시 → Base58Check
//! 4. SegWit: Bech32 인코딩 (witness version 0)

use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, SecretKey, PublicKey};

use crate::bip32::{master_key_from_seed, ExtendedPrivateKey};
use crate::bip39::mnemonic_to_seed;
use crate::utils::bech32::encode_bech32;

/// Bitcoin 계정
#[derive(Debug, Clone)]
pub struct BitcoinAccount {
    /// 개인키 (32바이트)
    pub private_key: [u8; 32],
    /// 압축 공개키 (33바이트)
    pub public_key: [u8; 33],
    /// 공개키 해시 (20바이트) - HASH160(pubkey)
    pub pubkey_hash: [u8; 20],
}

/// Bitcoin 기본 도출 경로 (SegWit)
pub const BITCOIN_SEGWIT_PATH: &str = "m/84'/0'/0'/0/0";
/// Bitcoin Legacy 도출 경로
pub const BITCOIN_LEGACY_PATH: &str = "m/44'/0'/0'/0/0";

/// 네트워크 타입
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Network {
    /// 메인넷
    Mainnet,
    /// 테스트넷
    Testnet,
}

impl BitcoinAccount {
    /// 개인키에서 Bitcoin 계정 생성
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let public_key = private_key_to_public_key(&private_key);
        let pubkey_hash = hash160(&public_key);

        BitcoinAccount {
            private_key,
            public_key,
            pubkey_hash,
        }
    }

    /// 확장 개인키에서 Bitcoin 계정 생성
    pub fn from_extended_key(extended_key: &ExtendedPrivateKey) -> Self {
        Self::from_private_key(extended_key.private_key)
    }

    /// 시드에서 Bitcoin 계정 생성 (SegWit 기본)
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        Self::from_seed_with_path(seed, BITCOIN_SEGWIT_PATH)
    }

    /// 시드에서 특정 경로로 Bitcoin 계정 생성
    pub fn from_seed_with_path(seed: &[u8], path: &str) -> Result<Self, String> {
        let master = master_key_from_seed(seed)?;
        let derived = master.derive_path(path)?;
        Ok(Self::from_extended_key(&derived))
    }

    /// 니모닉에서 Bitcoin 계정 생성
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, String> {
        let seed = mnemonic_to_seed(mnemonic, passphrase);
        Self::from_seed(&seed)
    }

    /// 니모닉에서 Legacy 계정 생성
    pub fn from_mnemonic_legacy(mnemonic: &str, passphrase: &str) -> Result<Self, String> {
        let seed = mnemonic_to_seed(mnemonic, passphrase);
        Self::from_seed_with_path(&seed, BITCOIN_LEGACY_PATH)
    }

    // ═══════════════════════════════════════════════════════════════
    // 주소 생성 메서드
    // ═══════════════════════════════════════════════════════════════

    /// SegWit 주소 (bc1...) - Bech32
    pub fn address_segwit(&self, network: Network) -> String {
        let hrp = match network {
            Network::Mainnet => "bc",
            Network::Testnet => "tb",
        };
        encode_bech32(hrp, Some(0), &self.pubkey_hash)
    }

    /// Legacy 주소 (1...) - Base58Check
    pub fn address_legacy(&self, network: Network) -> String {
        let version = match network {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6F,
        };
        encode_base58check(version, &self.pubkey_hash)
    }

    /// 기본 주소 (SegWit 메인넷)
    pub fn address(&self) -> String {
        self.address_segwit(Network::Mainnet)
    }

    /// 개인키를 WIF 형식으로 반환
    pub fn private_key_wif(&self, network: Network, compressed: bool) -> String {
        let version = match network {
            Network::Mainnet => 0x80,
            Network::Testnet => 0xEF,
        };

        let mut data = vec![version];
        data.extend_from_slice(&self.private_key);
        if compressed {
            data.push(0x01); // 압축 공개키 표시
        }

        // Base58Check 인코딩
        let checksum = double_sha256(&data);
        data.extend_from_slice(&checksum[..4]);
        bs58::encode(data).into_string()
    }

    /// 개인키를 hex 문자열로 반환
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }

    /// 공개키를 hex 문자열로 반환
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
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

/// Double SHA256
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);

    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Base58Check 인코딩
///
/// ## 구조
/// version (1바이트) + payload + checksum (4바이트)
/// checksum = double_sha256(version + payload)[0..4]
fn encode_base58check(version: u8, payload: &[u8]) -> String {
    let mut data = vec![version];
    data.extend_from_slice(payload);

    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[..4]);

    bs58::encode(data).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // SegWit 계정
        let account = BitcoinAccount::from_mnemonic(mnemonic, "").unwrap();

        println!("=== Bitcoin SegWit (m/84'/0'/0'/0/0) ===");
        println!("개인키: {}", account.private_key_hex());
        println!("공개키: {}", account.public_key_hex());
        println!("SegWit 주소: {}", account.address_segwit(Network::Mainnet));
        println!("WIF: {}", account.private_key_wif(Network::Mainnet, true));

        // Legacy 계정
        let legacy = BitcoinAccount::from_mnemonic_legacy(mnemonic, "").unwrap();

        println!("\n=== Bitcoin Legacy (m/44'/0'/0'/0/0) ===");
        println!("개인키: {}", legacy.private_key_hex());
        println!("Legacy 주소: {}", legacy.address_legacy(Network::Mainnet));
    }

    #[test]
    fn test_hash160() {
        // 테스트 벡터: 압축 공개키의 HASH160
        let pubkey = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let hash = hash160(&pubkey);

        // 예상값: 751e76e8199196d454941c45d1b3a323f1433bd6
        assert_eq!(
            hex::encode(hash),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[test]
    fn test_base58check() {
        // HASH160 → Legacy 주소
        let pubkey_hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&pubkey_hash);

        let address = encode_base58check(0x00, &hash);

        // 예상값: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
        assert_eq!(address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_bech32() {
        // HASH160 → SegWit 주소
        let pubkey_hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let address = encode_bech32("bc", Some(0), &pubkey_hash);

        // 예상값: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");

        println!("\n=== Bitcoin SegWit 계정 목록 (첫 5개) ===\n");

        for i in 0..5 {
            let path = format!("m/84'/0'/0'/0/{}", i);
            let account = BitcoinAccount::from_seed_with_path(&seed, &path).unwrap();

            println!("경로: {}", path);
            println!("SegWit: {}", account.address_segwit(Network::Mainnet));
            println!("Legacy: {}", account.address_legacy(Network::Mainnet));
            println!("WIF: {}", account.private_key_wif(Network::Mainnet, true));
            println!();
        }
    }
}
