//! BIP-32: Hierarchical Deterministic Wallets
//!
//! 시드에서 마스터 키 생성 및 키 도출 경로 처리
//!
//! ## 흐름
//! 1. 시드 (512비트) → HMAC-SHA512 → 마스터 키 + 체인코드
//! 2. 마스터 키 + 경로 → 자식 키 도출
//! 3. 자식 키 → 공개키 → 주소

use hmac::{Hmac, Mac};
use sha2::Sha512;
use secp256k1::{Secp256k1, SecretKey, PublicKey};

/// HMAC-SHA512 타입 정의
type HmacSha512 = Hmac<Sha512>;

/// 확장 키 (Extended Key)
///
/// 개인키/공개키 + 체인코드로 구성
/// 체인코드는 자식 키 도출에 필요한 추가 엔트로피
#[derive(Debug, Clone)]
pub struct ExtendedPrivateKey {
    /// 개인키 (32바이트)
    pub private_key: [u8; 32],
    /// 체인코드 (32바이트) - 자식 키 도출용 추가 엔트로피
    pub chain_code: [u8; 32],
    /// 깊이 (마스터=0, 자식=1, 손자=2, ...)
    pub depth: u8,
    /// 부모 지문 (첫 4바이트)
    pub parent_fingerprint: [u8; 4],
    /// 자식 인덱스
    pub child_index: u32,
}

/// 확장 공개키
#[derive(Debug, Clone)]
pub struct ExtendedPublicKey {
    /// 공개키 (33바이트, 압축)
    pub public_key: [u8; 33],
    /// 체인코드 (32바이트)
    pub chain_code: [u8; 32],
    /// 깊이
    pub depth: u8,
    /// 부모 지문
    pub parent_fingerprint: [u8; 4],
    /// 자식 인덱스
    pub child_index: u32,
}

/// 키 도출 경로의 각 단계
#[derive(Debug, Clone, Copy)]
pub enum ChildIndex {
    /// 일반 도출 (0 ~ 2^31-1)
    Normal(u32),
    /// 강화 도출 (2^31 ~ 2^32-1)
    /// 아포스트로피(')로 표시: m/44'/60'/0'
    Hardened(u32),
}

impl ChildIndex {
    /// 실제 인덱스 값 반환
    pub fn to_u32(&self) -> u32 {
        match self {
            ChildIndex::Normal(i) => *i,
            ChildIndex::Hardened(i) => i + 0x80000000, // 2^31 더함
        }
    }

    /// 강화 도출인지 확인
    pub fn is_hardened(&self) -> bool {
        matches!(self, ChildIndex::Hardened(_))
    }
}

/// 시드에서 마스터 키 생성
///
/// ## 알고리즘
/// 1. HMAC-SHA512(key="Bitcoin seed", data=seed)
/// 2. 결과 64바이트를 반으로 나눔
///    - 앞 32바이트 → 마스터 개인키
///    - 뒤 32바이트 → 마스터 체인코드
pub fn master_key_from_seed(seed: &[u8]) -> Result<ExtendedPrivateKey, String> {
    // ═══════════════════════════════════════════════════════════════
    // HMAC-SHA512 계산
    // 키: "Bitcoin seed" (BIP-32 표준)
    // 데이터: 시드 (512비트 = 64바이트)
    // ═══════════════════════════════════════════════════════════════

    let mut hmac = HmacSha512::new_from_slice(b"Bitcoin seed")
        .map_err(|e| format!("HMAC 초기화 실패: {}", e))?;

    hmac.update(seed);
    let result = hmac.finalize().into_bytes();

    // ═══════════════════════════════════════════════════════════════
    // 64바이트 결과를 반으로 분할
    // ═══════════════════════════════════════════════════════════════

    let mut private_key = [0u8; 32];
    let mut chain_code = [0u8; 32];

    private_key.copy_from_slice(&result[..32]);   // 앞 32바이트 → 개인키
    chain_code.copy_from_slice(&result[32..]);    // 뒤 32바이트 → 체인코드

    // 개인키가 유효한지 검증 (secp256k1 곡선의 order보다 작아야 함)
    SecretKey::from_slice(&private_key)
        .map_err(|_| "유효하지 않은 개인키 (매우 드문 경우)")?;

    Ok(ExtendedPrivateKey {
        private_key,
        chain_code,
        depth: 0,                           // 마스터 키는 깊이 0
        parent_fingerprint: [0u8; 4],       // 부모 없음
        child_index: 0,                     // 인덱스 없음
    })
}

impl ExtendedPrivateKey {
    /// 자식 키 도출 (Child Key Derivation)
    ///
    /// ## 알고리즘
    /// - 강화 도출 (Hardened): HMAC-SHA512(chain_code, 0x00 || private_key || index)
    /// - 일반 도출 (Normal): HMAC-SHA512(chain_code, public_key || index)
    pub fn derive_child(&self, index: ChildIndex) -> Result<ExtendedPrivateKey, String> {
        let secp = Secp256k1::new();
        let parent_secret = SecretKey::from_slice(&self.private_key)
            .map_err(|_| "유효하지 않은 부모 개인키")?;

        // HMAC 입력 데이터 준비
        let mut data = Vec::with_capacity(37);

        if index.is_hardened() {
            // ═══════════════════════════════════════════════════════════
            // 강화 도출: 0x00 + 개인키 + 인덱스
            // 개인키가 필요하므로 공개키만으로는 도출 불가
            // ═══════════════════════════════════════════════════════════
            data.push(0x00);
            data.extend_from_slice(&self.private_key);
        } else {
            // ═══════════════════════════════════════════════════════════
            // 일반 도출: 공개키 + 인덱스
            // 공개키만으로도 자식 공개키 도출 가능 (xpub)
            // ═══════════════════════════════════════════════════════════
            let parent_public = PublicKey::from_secret_key(&secp, &parent_secret);
            data.extend_from_slice(&parent_public.serialize());
        }

        // 인덱스 추가 (빅엔디안 4바이트)
        data.extend_from_slice(&index.to_u32().to_be_bytes());

        // HMAC-SHA512 계산
        let mut hmac = HmacSha512::new_from_slice(&self.chain_code)
            .map_err(|e| format!("HMAC 초기화 실패: {}", e))?;
        hmac.update(&data);
        let result = hmac.finalize().into_bytes();

        // 결과 분할
        let mut child_key_add = [0u8; 32];
        let mut child_chain_code = [0u8; 32];
        child_key_add.copy_from_slice(&result[..32]);
        child_chain_code.copy_from_slice(&result[32..]);

        // ═══════════════════════════════════════════════════════════════
        // 자식 개인키 = 부모 개인키 + HMAC 결과 (mod n)
        // secp256k1 곡선 위에서의 덧셈
        // ═══════════════════════════════════════════════════════════════
        let mut child_secret = SecretKey::from_slice(&child_key_add)
            .map_err(|_| "유효하지 않은 키 추가값")?;

        child_secret = child_secret.add_tweak(&parent_secret.into())
            .map_err(|_| "키 덧셈 실패")?;

        let mut child_private_key = [0u8; 32];
        child_private_key.copy_from_slice(&child_secret.secret_bytes());

        // 부모 지문 계산 (공개키 해시의 첫 4바이트)
        let parent_public = PublicKey::from_secret_key(&secp, &parent_secret);
        let parent_fingerprint = fingerprint(&parent_public.serialize());

        Ok(ExtendedPrivateKey {
            private_key: child_private_key,
            chain_code: child_chain_code,
            depth: self.depth + 1,
            parent_fingerprint,
            child_index: index.to_u32(),
        })
    }

    /// 경로 문자열로 키 도출
    ///
    /// 예: "m/44'/60'/0'/0/0"
    pub fn derive_path(&self, path: &str) -> Result<ExtendedPrivateKey, String> {
        let indices = parse_path(path)?;

        let mut key = self.clone();
        for index in indices {
            key = key.derive_child(index)?;
        }

        Ok(key)
    }

    /// 공개키 추출
    pub fn public_key(&self) -> [u8; 33] {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&self.private_key).unwrap();
        let public = PublicKey::from_secret_key(&secp, &secret);
        public.serialize()
    }

    /// 비압축 공개키 추출 (65바이트)
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&self.private_key).unwrap();
        let public = PublicKey::from_secret_key(&secp, &secret);
        public.serialize_uncompressed()
    }
}

/// 경로 문자열 파싱
///
/// "m/44'/60'/0'/0/0" → [Hardened(44), Hardened(60), Hardened(0), Normal(0), Normal(0)]
pub fn parse_path(path: &str) -> Result<Vec<ChildIndex>, String> {
    let path = path.trim();

    // "m" 또는 "M"으로 시작해야 함
    if !path.starts_with('m') && !path.starts_with('M') {
        return Err("경로는 'm'으로 시작해야 합니다".to_string());
    }

    let parts: Vec<&str> = path.split('/').collect();
    let mut indices = Vec::new();

    // 첫 번째 "m"은 건너뜀
    for part in parts.iter().skip(1) {
        if part.is_empty() {
            continue;
        }

        let (num_str, is_hardened) = if part.ends_with('\'') || part.ends_with('h') || part.ends_with('H') {
            // 강화 도출: 44', 44h, 44H
            (&part[..part.len()-1], true)
        } else {
            (*part, false)
        };

        let num: u32 = num_str.parse()
            .map_err(|_| format!("유효하지 않은 인덱스: {}", part))?;

        if is_hardened {
            indices.push(ChildIndex::Hardened(num));
        } else {
            indices.push(ChildIndex::Normal(num));
        }
    }

    Ok(indices)
}

/// 공개키 지문 계산 (HASH160의 첫 4바이트)
fn fingerprint(public_key: &[u8]) -> [u8; 4] {
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;

    // HASH160 = RIPEMD160(SHA256(public_key))
    let sha256_hash = Sha256::digest(public_key);
    let ripemd_hash = Ripemd160::digest(sha256_hash);

    let mut fp = [0u8; 4];
    fp.copy_from_slice(&ripemd_hash[..4]);
    fp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_from_seed() {
        // BIP-32 테스트 벡터 1
        // 시드: 000102030405060708090a0b0c0d0e0f
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = master_key_from_seed(&seed).unwrap();

        println!("마스터 개인키: {}", hex::encode(master.private_key));
        println!("마스터 체인코드: {}", hex::encode(master.chain_code));
        println!("마스터 공개키: {}", hex::encode(master.public_key()));

        // 예상값 (BIP-32 테스트 벡터)
        assert_eq!(
            hex::encode(master.private_key),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
    }

    #[test]
    fn test_derive_path() {
        // BIP-39 테스트 시드 (abandon x 11 + about)
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap();

        let master = master_key_from_seed(&seed).unwrap();

        // EVM 경로: m/44'/60'/0'/0/0
        let derived = master.derive_path("m/44'/60'/0'/0/0").unwrap();

        println!("EVM 개인키: {}", hex::encode(derived.private_key));
        println!("EVM 공개키: {}", hex::encode(derived.public_key()));
    }

    #[test]
    fn test_parse_path() {
        let indices = parse_path("m/44'/60'/0'/0/0").unwrap();

        assert_eq!(indices.len(), 5);
        assert!(indices[0].is_hardened()); // 44'
        assert!(indices[1].is_hardened()); // 60'
        assert!(indices[2].is_hardened()); // 0'
        assert!(!indices[3].is_hardened()); // 0
        assert!(!indices[4].is_hardened()); // 0
    }
}
