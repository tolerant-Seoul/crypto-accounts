//! # Bech32 Encoding
//!
//! BIP-173 Bech32 인코딩 구현
//!
//! ## 사용처
//! - **Bitcoin SegWit**: bc1... (witness_version = Some(0))
//! - **Cosmos SDK**: cosmos1..., osmo1... (witness_version = None)
//! - **Sui**: suiprivkey... (witness_version = None)
//!
//! ## Bech32의 장점
//! - **에러 검출**: 최대 4개 문자 삽입/삭제 검출 가능
//! - **대소문자 무관**: QR 코드에 효율적
//! - **구분자**: '1'로 HRP와 데이터 분리
//!
//! ## 참고 자료
//! - [BIP-173: Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)

/// Bech32 인코딩
///
/// HRP(Human-Readable Part) + 구분자('1') + 데이터(5비트) + 체크섬(6문자)
///
/// # Arguments
///
/// * `hrp` - Human-Readable Part (예: "bc", "cosmos", "suiprivkey")
/// * `witness_version` - Bitcoin SegWit 전용, None이면 일반 Bech32
/// * `data` - 인코딩할 데이터 (8비트 배열)
///
/// # Returns
///
/// Bech32 인코딩된 문자열 (소문자)
///
/// # Examples
///
/// ```
/// use crypto_lib::utils::bech32::encode_bech32;
///
/// // Bitcoin SegWit (witness_version = 0)
/// let pubkey_hash = [0u8; 20];
/// let address = encode_bech32("bc", Some(0), &pubkey_hash);
/// assert!(address.starts_with("bc1"));
///
/// // Cosmos (witness_version = None)
/// let address = encode_bech32("cosmos", None, &pubkey_hash);
/// assert!(address.starts_with("cosmos1"));
/// ```
pub fn encode_bech32(hrp: &str, witness_version: Option<u8>, data: &[u8]) -> String {
    // 8비트 → 5비트 변환
    let mut bits: Vec<u8> = match witness_version {
        Some(version) => {
            let mut v = vec![version];
            v.extend(convert_bits(data, 8, 5, true));
            v
        }
        None => convert_bits(data, 8, 5, true),
    };

    // Bech32 체크섬 계산
    let checksum = bech32_checksum(hrp, &bits);
    bits.extend(checksum);

    // 문자로 변환 (Bech32 charset)
    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let encoded: String = bits
        .iter()
        .map(|&b| charset.chars().nth(b as usize).unwrap())
        .collect();

    format!("{}1{}", hrp, encoded)
}

/// 비트 변환 (8비트 ↔ 5비트)
///
/// Bech32는 5비트 단위로 인코딩하므로 8비트 데이터를 5비트로 변환 필요
///
/// # Arguments
///
/// * `data` - 변환할 데이터
/// * `from_bits` - 입력 비트 수 (보통 8)
/// * `to_bits` - 출력 비트 수 (보통 5)
/// * `pad` - 패딩 여부 (마지막 비트가 부족할 때)
fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut result = Vec::new();
    let max_v = (1u32 << to_bits) - 1;

    for &value in data {
        acc = (acc << from_bits) | (value as u32);
        bits += from_bits;

        while bits >= to_bits {
            bits -= to_bits;
            result.push(((acc >> bits) & max_v) as u8);
        }
    }

    if pad && bits > 0 {
        result.push(((acc << (to_bits - bits)) & max_v) as u8);
    }

    result
}

/// Bech32 체크섬 계산
///
/// 6문자의 체크섬을 생성하여 오류 검출
///
/// # Arguments
///
/// * `hrp` - Human-Readable Part
/// * `data` - 5비트 데이터
///
/// # Returns
///
/// 6바이트 체크섬 (각 바이트는 0-31 범위)
fn bech32_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend(data);
    values.extend(vec![0u8; 6]);

    let polymod = bech32_polymod(&values) ^ 1;

    (0..6)
        .map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

/// HRP 확장 (Bech32 체크섬 계산용)
///
/// HRP의 각 문자를 상위 5비트와 하위 5비트로 분리
///
/// # Arguments
///
/// * `hrp` - Human-Readable Part
///
/// # Returns
///
/// 확장된 HRP 배열
fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut result: Vec<u8> = hrp.chars().map(|c| (c as u8) >> 5).collect();
    result.push(0);
    result.extend(hrp.chars().map(|c| (c as u8) & 31));
    result
}

/// Bech32 다항식 모듈러 연산
///
/// 오류 검출 코드의 핵심 알고리즘
/// BCH 코드 기반의 체크섬 계산
///
/// # Arguments
///
/// * `values` - HRP 확장 + 데이터 + 체크섬 플레이스홀더
///
/// # Returns
///
/// 다항식 모듈러 결과 (체크섬 계산에 사용)
fn bech32_polymod(values: &[u8]) -> u32 {
    let generator = [0x3b6a57b2u32, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;

    for &value in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (value as u32);

        for (i, &gen) in generator.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }

    chk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bech32_bitcoin_segwit() {
        // Bitcoin SegWit 주소 테스트
        // HASH160 → bc1...
        let pubkey_hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let address = encode_bech32("bc", Some(0), &pubkey_hash);

        // BIP-173 테스트 벡터
        assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_bech32_cosmos() {
        // Cosmos 주소 테스트
        let pubkey_hash = [0u8; 20];
        let address = encode_bech32("cosmos", None, &pubkey_hash);

        assert!(address.starts_with("cosmos1"));
        assert_eq!(address.len(), 45); // "cosmos1" + 38문자
    }

    #[test]
    fn test_bech32_sui_privkey() {
        // Sui 개인키 인코딩 테스트
        let privkey_with_flag = [0u8; 33]; // 플래그 + 32바이트 개인키
        let encoded = encode_bech32("suiprivkey", None, &privkey_with_flag);

        assert!(encoded.starts_with("suiprivkey1"));
    }

    #[test]
    fn test_convert_bits() {
        // 8비트 → 5비트 변환 테스트
        let data = vec![0xFF, 0xFF];
        let converted = convert_bits(&data, 8, 5, true);

        // 0xFF 0xFF = 11111111 11111111 (16비트)
        // → 11111 11111 11111 10000 (5비트 x 4, 마지막 패딩)
        // = 31, 31, 31, 16
        assert_eq!(converted, vec![31, 31, 31, 16]);
    }

    #[test]
    fn test_hrp_expand() {
        // HRP 확장 테스트
        let expanded = bech32_hrp_expand("bc");

        // 'b' = 0x62 = 0b01100010
        // 'c' = 0x63 = 0b01100011
        // → [상위5비트, 상위5비트, 0, 하위5비트, 하위5비트]
        assert_eq!(expanded, vec![3, 3, 0, 2, 3]);
    }
}
