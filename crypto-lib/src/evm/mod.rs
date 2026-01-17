//! EVM Account Generation (Ethereum, Polygon, BSC, etc.)
//!
//! - 타원곡선: secp256k1
//! - 해시: Keccak-256
//! - 주소 형식: 20바이트 (0x...)
//! - BIP-44 경로: m/44'/60'/0'/0/0
//!
//! ## 주소 생성 과정
//! 1. 개인키 → 공개키 (secp256k1)
//! 2. 비압축 공개키 (65바이트) → prefix 제거 (64바이트)
//! 3. Keccak-256 해시 (32바이트)
//! 4. 마지막 20바이트 = 주소
//! 5. EIP-55 체크섬 적용

use tiny_keccak::{Hasher, Keccak};
use crate::bip32::{master_key_from_seed, ExtendedPrivateKey};
use crate::bip39::{mnemonic_to_seed};

/// EVM 계정 (Ethereum, Polygon, BSC 등)
#[derive(Debug, Clone)]
pub struct EvmAccount {
    /// 개인키 (32바이트)
    pub private_key: [u8; 32],
    /// 공개키 (65바이트, 비압축)
    pub public_key: [u8; 65],
    /// 주소 (20바이트)
    pub address: [u8; 20],
}

/// EVM 기본 도출 경로
pub const EVM_PATH: &str = "m/44'/60'/0'/0/0";

impl EvmAccount {
    /// 개인키에서 EVM 계정 생성
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let public_key = private_key_to_public_key(&private_key);
        let address = public_key_to_address(&public_key);

        EvmAccount {
            private_key,
            public_key,
            address,
        }
    }

    /// 확장 개인키에서 EVM 계정 생성
    pub fn from_extended_key(extended_key: &ExtendedPrivateKey) -> Self {
        Self::from_private_key(extended_key.private_key)
    }

    /// 시드에서 EVM 계정 생성 (기본 경로 사용)
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        Self::from_seed_with_path(seed, EVM_PATH)
    }

    /// 시드에서 특정 경로로 EVM 계정 생성
    pub fn from_seed_with_path(seed: &[u8], path: &str) -> Result<Self, String> {
        let master = master_key_from_seed(seed)?;
        let derived = master.derive_path(path)?;
        Ok(Self::from_extended_key(&derived))
    }

    /// 니모닉에서 EVM 계정 생성
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, String> {
        let seed = mnemonic_to_seed(mnemonic, passphrase);
        Self::from_seed(&seed)
    }

    /// 주소를 체크섬이 적용된 문자열로 반환 (EIP-55)
    pub fn address_checksummed(&self) -> String {
        to_checksum_address(&self.address)
    }

    /// 주소를 소문자 문자열로 반환
    pub fn address_lowercase(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }

    /// 개인키를 hex 문자열로 반환
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }
}

/// 개인키 → 비압축 공개키 (secp256k1)
fn private_key_to_public_key(private_key: &[u8; 32]) -> [u8; 65] {
    use secp256k1::{Secp256k1, SecretKey, PublicKey};

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(private_key).expect("유효한 개인키");
    let public = PublicKey::from_secret_key(&secp, &secret);

    public.serialize_uncompressed()
}

/// 비압축 공개키 → EVM 주소
///
/// ## 알고리즘
/// 1. 공개키 (65바이트)에서 prefix(0x04) 제거 → 64바이트
/// 2. Keccak-256 해시 → 32바이트
/// 3. 마지막 20바이트 = 주소
fn public_key_to_address(public_key: &[u8; 65]) -> [u8; 20] {
    // ═══════════════════════════════════════════════════════════════
    // 1단계: prefix 제거 (0x04는 비압축 공개키 표시)
    // ═══════════════════════════════════════════════════════════════
    let public_key_no_prefix = &public_key[1..]; // 64바이트

    // ═══════════════════════════════════════════════════════════════
    // 2단계: Keccak-256 해시
    // ═══════════════════════════════════════════════════════════════
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(public_key_no_prefix);
    keccak.finalize(&mut hash);

    // ═══════════════════════════════════════════════════════════════
    // 3단계: 마지막 20바이트 추출
    // ═══════════════════════════════════════════════════════════════
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]); // 뒤 20바이트

    address
}

/// EIP-55 체크섬 주소 생성
///
/// ## 알고리즘
/// 1. 주소를 소문자 hex로 변환 (0x 없이)
/// 2. hex 문자열을 Keccak-256 해시
/// 3. 해시의 각 니블(4비트)이 8 이상이면 대문자, 아니면 소문자
fn to_checksum_address(address: &[u8; 20]) -> String {
    let address_hex = hex::encode(address); // 소문자 40자

    // 소문자 주소의 Keccak-256 해시
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(address_hex.as_bytes());
    keccak.finalize(&mut hash);

    // 체크섬 적용
    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");

    for (i, c) in address_hex.chars().enumerate() {
        // 해시의 i번째 니블 (4비트) 추출
        let hash_byte = hash[i / 2];
        let hash_nibble = if i % 2 == 0 {
            hash_byte >> 4  // 상위 4비트
        } else {
            hash_byte & 0x0F  // 하위 4비트
        };

        // 니블이 8 이상이면 대문자
        if hash_nibble >= 8 && c.is_ascii_alphabetic() {
            checksummed.push(c.to_ascii_uppercase());
        } else {
            checksummed.push(c);
        }
    }

    checksummed
}

/// Keccak-256 해시 유틸리티
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(data);
    keccak.finalize(&mut hash);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_from_mnemonic() {
        // BIP-39 테스트 니모닉 (abandon x 11 + about)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let account = EvmAccount::from_mnemonic(mnemonic, "").unwrap();

        println!("개인키: 0x{}", account.private_key_hex());
        println!("주소 (체크섬): {}", account.address_checksummed());
        println!("주소 (소문자): {}", account.address_lowercase());

        // 예상 주소 (Ian Coleman 사이트에서 확인 가능)
        // m/44'/60'/0'/0/0 경로
        let expected_address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
        assert_eq!(
            account.address_checksummed().to_lowercase(),
            expected_address.to_lowercase()
        );
    }

    #[test]
    fn test_checksum_address() {
        // EIP-55 테스트 벡터
        let test_cases = [
            // 전부 소문자 (체크섬 전)
            "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
        ];

        for hex_addr in test_cases {
            let bytes = hex::decode(hex_addr).unwrap();
            let mut address = [0u8; 20];
            address.copy_from_slice(&bytes);

            let checksummed = to_checksum_address(&address);
            println!("{} → {}", hex_addr, checksummed);
        }
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");

        println!("\n=== EVM 계정 목록 (첫 5개) ===\n");

        for i in 0..5 {
            let path = format!("m/44'/60'/0'/0/{}", i);
            let account = EvmAccount::from_seed_with_path(&seed, &path).unwrap();

            println!("경로: {}", path);
            println!("주소: {}", account.address_checksummed());
            println!("개인키: 0x{}", account.private_key_hex());
            println!();
        }
    }
}
