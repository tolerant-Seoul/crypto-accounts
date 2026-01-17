//! # SLIP-10 Ed25519 Key Derivation
//!
//! SLIP-10은 BIP-32의 Ed25519 버전입니다.
//!
//! ## 사용처
//! - **Solana**: Ed25519 개인키 도출
//! - **Sui**: Ed25519 개인키 도출
//!
//! ## BIP-32 vs SLIP-10
//!
//! | 특성 | BIP-32 | SLIP-10 |
//! |------|--------|---------|
//! | 곡선 | secp256k1 | Ed25519 |
//! | 도출 방식 | 일반 + 강화 | **강화만** |
//! | HMAC 키 | "Bitcoin seed" | "ed25519 seed" |
//!
//! ## 왜 Ed25519는 강화 도출만 가능한가?
//!
//! Ed25519는 **Twisted Edwards Curve**로, secp256k1과 달리:
//! - 개인키에서 공개키 도출 시 해싱 과정 포함
//! - 개인키와 공개키 간 선형 관계 없음
//! - 일반 도출(공개키만으로 자식 키 생성) 수학적으로 불가능
//!
//! ## 참고 자료
//! - [SLIP-10: Universal private key derivation from master private key](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)

use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// SLIP-10 Ed25519 개인키 도출
///
/// 시드와 경로로부터 Ed25519 개인키를 도출합니다.
///
/// # Arguments
///
/// * `seed` - BIP-39 시드 (512비트 / 64바이트)
/// * `path` - 도출 경로 (예: "m/44'/501'/0'/0'")
///
/// # Returns
///
/// Ed25519 개인키 (32바이트) 또는 오류 메시지
///
/// # Examples
///
/// ```
/// use crypto_lib::utils::slip10::derive_ed25519_key;
/// use crypto_lib::bip39::mnemonic_to_seed;
///
/// let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// let seed = mnemonic_to_seed(mnemonic, "");
///
/// // Solana 경로
/// let key = derive_ed25519_key(&seed, "m/44'/501'/0'/0'").unwrap();
/// assert_eq!(key.len(), 32);
/// ```
///
/// # Errors
///
/// - 경로 파싱 실패 (잘못된 형식)
/// - HMAC 초기화 실패
pub fn derive_ed25519_key(seed: &[u8], path: &str) -> Result<[u8; 32], String> {
    let indices = parse_slip10_path(path)?;

    let (mut key, mut chain_code) = slip10_master_key(seed)?;

    for index in indices {
        let (new_key, new_chain_code) = slip10_derive_child(&key, &chain_code, index)?;
        key = new_key;
        chain_code = new_chain_code;
    }

    Ok(key)
}

/// SLIP-10 경로 파싱
///
/// BIP-44 스타일 경로를 인덱스 배열로 변환합니다.
///
/// # Arguments
///
/// * `path` - 도출 경로 (예: "m/44'/501'/0'/0'")
///
/// # Returns
///
/// 인덱스 배열 (예: [44, 501, 0, 0])
///
/// # Examples
///
/// ```
/// use crypto_lib::utils::slip10::parse_slip10_path;
///
/// let indices = parse_slip10_path("m/44'/501'/0'/0'").unwrap();
/// assert_eq!(indices, vec![44, 501, 0, 0]);
///
/// // 강화 표시는 제거됨 (Ed25519는 모두 강화 도출)
/// let indices2 = parse_slip10_path("m/44/501/0/0").unwrap();
/// assert_eq!(indices2, vec![44, 501, 0, 0]);
/// ```
///
/// # Errors
///
/// - 경로가 'm'으로 시작하지 않음
/// - 유효하지 않은 인덱스 (숫자가 아님)
pub fn parse_slip10_path(path: &str) -> Result<Vec<u32>, String> {
    let path = path.trim();

    if !path.starts_with('m') && !path.starts_with('M') {
        return Err("경로는 'm'으로 시작해야 합니다".to_string());
    }

    let parts: Vec<&str> = path.split('/').collect();
    let mut indices = Vec::new();

    for part in parts.iter().skip(1) {
        if part.is_empty() {
            continue;
        }

        // 강화 도출 표시 제거 (Ed25519는 모두 강화 도출)
        let num_str = part
            .trim_end_matches('\'')
            .trim_end_matches('h')
            .trim_end_matches('H');

        let num: u32 = num_str
            .parse()
            .map_err(|_| format!("유효하지 않은 인덱스: {}", part))?;

        indices.push(num);
    }

    Ok(indices)
}

// ═══════════════════════════════════════════════════════════════
// Internal Functions
// ═══════════════════════════════════════════════════════════════

/// SLIP-10 마스터 키 생성
///
/// HMAC-SHA512(key="ed25519 seed", data=seed)
///
/// # Arguments
///
/// * `seed` - BIP-39 시드
///
/// # Returns
///
/// (개인키 32바이트, 체인코드 32바이트)
fn slip10_master_key(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let mut hmac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|e| format!("HMAC 초기화 실패: {}", e))?;

    hmac.update(seed);
    let result = hmac.finalize().into_bytes();

    let mut private_key = [0u8; 32];
    let mut chain_code = [0u8; 32];

    private_key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    Ok((private_key, chain_code))
}

/// SLIP-10 자식 키 도출 (강화 도출만)
///
/// Ed25519는 강화 도출만 사용 (곡선 특성상 일반 도출 불가)
///
/// # Arguments
///
/// * `parent_key` - 부모 개인키 (32바이트)
/// * `parent_chain_code` - 부모 체인코드 (32바이트)
/// * `index` - 자식 인덱스 (0부터 시작, 자동으로 0x80000000 OR 연산)
///
/// # Returns
///
/// (자식 개인키 32바이트, 자식 체인코드 32바이트)
fn slip10_derive_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), String> {
    // 강화 인덱스 (0x80000000 이상)
    let hardened_index = index | 0x80000000;

    // HMAC 입력: 0x00 + 개인키 + 인덱스
    let mut data = Vec::with_capacity(37);
    data.push(0x00);
    data.extend_from_slice(parent_key);
    data.extend_from_slice(&hardened_index.to_be_bytes());

    let mut hmac = HmacSha512::new_from_slice(parent_chain_code)
        .map_err(|e| format!("HMAC 초기화 실패: {}", e))?;

    hmac.update(&data);
    let result = hmac.finalize().into_bytes();

    let mut child_key = [0u8; 32];
    let mut child_chain_code = [0u8; 32];

    child_key.copy_from_slice(&result[..32]);
    child_chain_code.copy_from_slice(&result[32..]);

    Ok((child_key, child_chain_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slip10_master_key() {
        // SLIP-10 공식 테스트 벡터
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (key, chain_code) = slip10_master_key(&seed).unwrap();

        // SLIP-10 예상값 (Ed25519)
        assert_eq!(
            hex::encode(key),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(chain_code),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
    }

    #[test]
    fn test_parse_slip10_path() {
        // 강화 도출 표시 포함
        let indices = parse_slip10_path("m/44'/501'/0'/0'").unwrap();
        assert_eq!(indices, vec![44, 501, 0, 0]);

        // 강화 도출 표시 없음 (Ed25519는 어차피 모두 강화)
        let indices2 = parse_slip10_path("m/44/501/0/0").unwrap();
        assert_eq!(indices2, vec![44, 501, 0, 0]);

        // 'H' 표기
        let indices3 = parse_slip10_path("m/44H/501H/0H/0H").unwrap();
        assert_eq!(indices3, vec![44, 501, 0, 0]);
    }

    #[test]
    fn test_derive_child() {
        let parent_key = [0u8; 32];
        let parent_chain_code = [1u8; 32];

        let (child_key, child_chain_code) = slip10_derive_child(&parent_key, &parent_chain_code, 0).unwrap();

        // 자식 키는 부모와 달라야 함
        assert_ne!(child_key, parent_key);
        assert_ne!(child_chain_code, parent_chain_code);

        // 같은 입력은 같은 출력
        let (child_key2, child_chain_code2) = slip10_derive_child(&parent_key, &parent_chain_code, 0).unwrap();
        assert_eq!(child_key, child_key2);
        assert_eq!(child_chain_code, child_chain_code2);

        // 다른 인덱스는 다른 출력
        let (child_key3, _) = slip10_derive_child(&parent_key, &parent_chain_code, 1).unwrap();
        assert_ne!(child_key, child_key3);
    }

    #[test]
    fn test_derive_ed25519_key() {
        use crate::bip39::mnemonic_to_seed;

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");

        // Solana 경로
        let key = derive_ed25519_key(&seed, "m/44'/501'/0'/0'").unwrap();
        assert_eq!(key.len(), 32);

        // Sui 경로
        let key2 = derive_ed25519_key(&seed, "m/44'/784'/0'/0'/0'").unwrap();
        assert_eq!(key2.len(), 32);

        // 경로가 다르면 키도 다름
        assert_ne!(key, key2);
    }

    #[test]
    fn test_invalid_path() {
        // 'm'으로 시작하지 않음
        assert!(parse_slip10_path("44'/501'/0'/0'").is_err());

        // 유효하지 않은 인덱스
        assert!(parse_slip10_path("m/abc/501/0/0").is_err());
    }
}
