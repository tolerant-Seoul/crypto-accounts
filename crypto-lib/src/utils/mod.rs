//! # Utility Modules
//!
//! 블록체인 계정 생성에 사용되는 공통 유틸리티 함수들
//!
//! ## 모듈 구성
//!
//! ### bech32
//! Bech32 인코딩 - Bitcoin SegWit, Cosmos, Sui에서 사용
//! - BIP-173 표준 구현
//! - 에러 검출 능력이 뛰어남 (최대 4개 문자 삽입/삭제 검출)
//! - 대소문자 무관 (소문자 권장)
//!
//! ### slip10
//! SLIP-10 Ed25519 키 도출 - Solana, Sui에서 사용
//! - BIP-32의 Ed25519 버전
//! - 강화 도출(Hardened Derivation)만 지원
//! - 곡선 특성상 일반 도출 불가능

pub mod bech32;
pub mod slip10;
