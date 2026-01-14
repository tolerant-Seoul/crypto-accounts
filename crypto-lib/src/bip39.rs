//! BIP-39: Mnemonic Code for Generating Deterministic Keys
//!
//! 니모닉(12/24 단어) 생성 및 시드 도출
//!
//! ## 흐름
//! 1. 엔트로피 생성 (128/256 비트)
//! 2. 체크섬 추가 (SHA-256 해시의 앞 4/8비트)
//! 3. 11비트씩 분할하여 단어 인덱스로 변환
//! 4. PBKDF2로 시드 생성

use sha2::{Sha256, Sha512, Digest};
use hmac::Hmac;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;

/// BIP-39 영어 단어 목록 (2048개)
pub const WORDLIST_ENGLISH: &str = include_str!("wordlist/english.txt");

/// 엔트로피 크기
#[derive(Debug, Clone, Copy)]
pub enum MnemonicType {
    /// 128비트 → 12단어
    Words12,
    /// 256비트 → 24단어
    Words24,
}

impl MnemonicType {
    /// 엔트로피 바이트 수
    pub fn entropy_bytes(&self) -> usize {
        match self {
            MnemonicType::Words12 => 16,  // 128비트
            MnemonicType::Words24 => 32,  // 256비트
        }
    }

    /// 체크섬 비트 수
    pub fn checksum_bits(&self) -> usize {
        match self {
            MnemonicType::Words12 => 4,
            MnemonicType::Words24 => 8,
        }
    }

    /// 총 단어 수
    pub fn word_count(&self) -> usize {
        match self {
            MnemonicType::Words12 => 12,
            MnemonicType::Words24 => 24,
        }
    }
}

/// 단어 목록을 벡터로 파싱
pub fn parse_wordlist(wordlist: &str) -> Vec<&str> {
    wordlist.lines().collect()
}

/// 랜덤 엔트로피 생성
pub fn generate_entropy(mnemonic_type: MnemonicType) -> Vec<u8> {
    let mut entropy = vec![0u8; mnemonic_type.entropy_bytes()];
    rand::thread_rng().fill_bytes(&mut entropy);
    entropy
}

/// 엔트로피에서 체크섬 계산
///
/// SHA-256(entropy)의 앞 N비트를 체크섬으로 사용
/// - 128비트 엔트로피 → 4비트 체크섬
/// - 256비트 엔트로피 → 8비트 체크섬
pub fn calculate_checksum(entropy: &[u8]) -> u8 {
    let hash = Sha256::digest(entropy);
    // 엔트로피 길이에 따라 체크섬 비트 수 결정
    // 128비트(16바이트) → 4비트, 256비트(32바이트) → 8비트
    let checksum_bits = entropy.len() / 4; // bytes * 8 / 32 = bytes / 4

    // 해시의 첫 바이트에서 필요한 비트만 추출
    hash[0] >> (8 - checksum_bits)
}

/// 엔트로피를 니모닉 단어 인덱스로 변환
///
/// ## 알고리즘
/// 1. 엔트로피 + 체크섬을 하나의 비트 배열로 변환
/// 2. 11비트씩 분할하여 각각을 정수로 변환
/// 3. 각 정수가 단어 목록의 인덱스가 됨 (0~2047)
pub fn entropy_to_indices(entropy: &[u8], checksum: u8) -> Vec<u16> {
    // ═══════════════════════════════════════════════════════════════
    // 1단계: 엔트로피 + 체크섬을 비트 배열로 변환
    // ═══════════════════════════════════════════════════════════════
    //
    // 가장 명확한 방법: 모든 비트를 bool 배열로 풀어헤침
    // (성능보다 정확성과 가독성 우선)

    let checksum_bits = entropy.len() / 4;  // 16바이트 → 4비트

    // 모든 비트를 담을 벡터
    let mut bits: Vec<bool> = Vec::new();

    // 엔트로피의 모든 비트를 추가 (MSB first)
    for byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }

    // 체크섬 비트 추가
    // checksum은 이미 오른쪽 정렬된 값 (예: 4비트면 0~15 범위)
    // MSB부터 추가해야 하므로 (checksum_bits-1)부터 0까지
    for i in (0..checksum_bits).rev() {
        bits.push((checksum >> i) & 1 == 1);
    }

    // ═══════════════════════════════════════════════════════════════
    // 2단계: 11비트씩 묶어서 인덱스로 변환
    // ═══════════════════════════════════════════════════════════════
    //
    // 예시: bits = [true, false, true, true, ...]
    //       11개씩 묶어서 이진수 → 십진수 변환

    let word_count = bits.len() / 11;
    let mut indices: Vec<u16> = Vec::with_capacity(word_count);

    for i in 0..word_count {
        let mut index: u16 = 0;

        // 11비트를 하나의 숫자로 조합
        for j in 0..11 {
            index <<= 1;                      // 왼쪽으로 1비트 시프트
            if bits[i * 11 + j] {
                index |= 1;                   // 현재 비트가 1이면 추가
            }
        }

        indices.push(index);
    }

    indices
}

/// 인덱스를 니모닉 문자열로 변환
pub fn indices_to_mnemonic(indices: &[u16], wordlist: &[&str]) -> String {
    indices
        .iter()
        .map(|&idx| wordlist[idx as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

/// 니모닉에서 시드 생성 (PBKDF2-HMAC-SHA512)
///
/// - 반복 횟수: 2048
/// - 솔트: "mnemonic" + 패스프레이즈
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let salt = format!("mnemonic{}", passphrase);
    let mut seed = [0u8; 64];

    pbkdf2_hmac::<Sha512>(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed,
    );

    seed
}

/// 전체 플로우: 엔트로피 → 니모닉 → 시드
pub fn generate_mnemonic(mnemonic_type: MnemonicType) -> (String, [u8; 64]) {
    let wordlist = parse_wordlist(WORDLIST_ENGLISH);
    let entropy = generate_entropy(mnemonic_type);
    let checksum = calculate_checksum(&entropy);
    let indices = entropy_to_indices(&entropy, checksum);
    let mnemonic = indices_to_mnemonic(&indices, &wordlist);
    let seed = mnemonic_to_seed(&mnemonic, "");

    (mnemonic, seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_vector_1() {
        // ═══════════════════════════════════════════════════════════════
        // BIP-39 공식 테스트 벡터 #1
        // 엔트로피: 00000000000000000000000000000000 (128비트, 모두 0)
        // 예상 니모닉: "abandon" x 11 + "about"
        // ═══════════════════════════════════════════════════════════════

        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let checksum = calculate_checksum(&entropy);
        let indices = entropy_to_indices(&entropy, checksum);
        let wordlist = parse_wordlist(WORDLIST_ENGLISH);
        let mnemonic = indices_to_mnemonic(&indices, &wordlist);

        println!("엔트로피: {}", hex::encode(&entropy));
        println!("체크섬: {:08b}", checksum);
        println!("인덱스: {:?}", indices);
        println!("니모닉: {}", mnemonic);

        // 검증
        let expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(mnemonic, expected);
    }

    #[test]
    fn test_bip39_vector_2() {
        // ═══════════════════════════════════════════════════════════════
        // BIP-39 공식 테스트 벡터 #2
        // 엔트로피: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
        // ═══════════════════════════════════════════════════════════════

        let entropy = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let checksum = calculate_checksum(&entropy);
        let indices = entropy_to_indices(&entropy, checksum);
        let wordlist = parse_wordlist(WORDLIST_ENGLISH);
        let mnemonic = indices_to_mnemonic(&indices, &wordlist);

        println!("니모닉: {}", mnemonic);

        let expected = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_eq!(mnemonic, expected);
    }

    #[test]
    fn test_mnemonic_to_seed() {
        // ═══════════════════════════════════════════════════════════════
        // 시드 생성 테스트 (PBKDF2-HMAC-SHA512)
        // ═══════════════════════════════════════════════════════════════

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");

        println!("시드: {}", hex::encode(seed));

        // BIP-39 공식 테스트 벡터의 예상 시드
        let expected_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        assert_eq!(hex::encode(seed), expected_seed);
    }
}
