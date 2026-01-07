# Chain-Specific Address Generation

This document outlines the specific address generation methods for various cryptocurrencies, building upon the foundation of BIP-32, BIP-39, and BIP-44. While these BIPs provide a standardized way to generate master keys and derive child keys, the final step of creating a public address from a public key is often unique to each blockchain.

This document will cover the address generation process for several major cryptocurrencies.

## Bitcoin

Bitcoin has several address formats. The address format is determined by the script used to spend the bitcoins.

### P2PKH (Pay-to-Public-Key-Hash)

This is the original address format. P2PKH addresses start with a `1`.

1.  **Generate Keys**: Start with a private key and generate the corresponding public key.
2.  **Hashing**: The public key is first hashed with SHA-256 and then with RIPEMD-160.
3.  **Versioning**: A version byte (`0x00` for mainnet) is prepended to the hash.
4.  **Checksum**: The double-SHA256 hash of the versioned hash is calculated, and the first 4 bytes are taken as a checksum.
5.  **Encoding**: The versioned hash and the checksum are concatenated and then encoded using Base58Check.

### P2SH (Pay-to-Script-Hash)

P2SH addresses are more flexible and can be used for multi-signature wallets. They start with a `3`.

1.  **Redeem Script**: Create a `redeemScript` that specifies the conditions for spending the funds.
2.  **Hashing**: The `redeemScript` is hashed with SHA-256 and then with RIPEMD-160.
3.  **Versioning**: A version byte (`0x05` for mainnet) is prepended to the script hash.
4.  **Checksum**: A checksum is calculated in the same way as for P2PKH.
5.  **Encoding**: The versioned script hash and the checksum are concatenated and then encoded using Base58Check.

### Bech32 (Native SegWit)

Bech32 is the native SegWit address format, which provides better efficiency and error detection. These addresses start with `bc1`.

1.  **Witness Program**: The public key is hashed (SHA-256 then RIPEMD-160) to create a 20-byte witness program.
2.  **Encoding**: The address is encoded using the Bech32 format, which includes a human-readable part (`bc` for mainnet), a witness version (`0`), and the witness program.

## Ethereum

Ethereum addresses are 42-character hexadecimal strings, prefixed with `0x`.

1.  **Generate Keys**: Start with a private key and generate the corresponding public key (64 bytes).
2.  **Hashing**: The public key is hashed using Keccak-256.
3.  **Truncate**: The last 20 bytes of the Keccak-256 hash are taken as the address.
4.  **Formatting**: The address is prefixed with `0x`.

Unlike Bitcoin, Ethereum does not have different address formats for different script types. All Ethereum addresses are generated in the same way.

## Ripple (XRP)

리플 주소는 `r`로 시작하며, 비트코인과 유사한 절차를 따르지만 자체 Base58 인코딩 사전을 사용합니다.

1.  **키 생성**: 개인키로부터 공개키를 생성합니다.
2.  **해싱**: 공개키를 `SHA-256`으로 해싱한 후, 그 결과를 `RIPEMD-160`으로 다시 해싱하여 "Account ID"를 생성합니다.
3.  **버전 부여**: Account ID 앞에 `0x00`이라는 주소 타입 접두사를 붙입니다.
4.  **체크섬**: 버전이 부여된 Account ID를 두 번 `SHA-256` 해싱한 후, 결과의 첫 4바이트를 체크섬으로 사용합니다.
5.  **인코딩**: 버전이 부여된 Account ID와 체크섬을 합친 후, 리플의 Base58 인코딩 방식으로 변환합니다.

### 데스티네이션 태그 (Destination Tag)

리플은 중앙화된 거래소 등에서 여러 고객의 자금을 하나의 주소로 관리할 때, 각 고객을 식별하기 위해 "데스티네이션 태그"라는 숫자 태그를 사용합니다. 이는 은행의 계좌 이체 시 메모나 참조 번호와 유사한 역할을 합니다.

## Stellar (XLM)

스텔라 주소는 `G`로 시작하며, 공개키 자체를 주소로 사용합니다.

1.  **키 생성**: Ed25519 알고리즘을 사용하여 개인키와 공개키 쌍을 생성합니다.
2.  **주소**: 생성된 공개키가 바로 스텔라 주소(계정 ID)입니다.
3.  **인코딩**: 이 공개키는 Base32로 인코딩되어 56자의 문자열로 표현됩니다.

### 메모 (Memo)

스텔라는 리플의 데스티네이션 태그와 유사하게 "메모" 기능을 제공합니다. 메모는 텍스트, 숫자 ID, 해시 등 다양한 형태로 거래에 추가 정보를 포함시키는 데 사용됩니다.

## Cardano (ADA)

카르다노 주소는 `addr1`로 시작하며, 지분 증명(PoS) 시스템을 지원하기 위해 복잡한 구조를 가집니다.

1.  **키 종류**: 카르다노는 두 종류의 키를 사용합니다.
    *   **지불 키 (Payment Key)**: 자금을 받는데 사용되는 주소 부분을 생성합니다.
    *   **지분 키 (Stake Key)**: 스테이킹 권한을 주소와 연결하여 위임 및 보상을 받는데 사용됩니다.
2.  **주소 생성**:
    *   **기본 주소 (Base Address)**: 지불 키와 지분 키를 모두 해싱하고 결합하여 생성합니다. 이를 통해 자금 수령과 스테이킹이 모두 가능합니다.
    *   **엔터프라이즈 주소 (Enterprise Address)**: 지불 키만 사용하여 생성하며, 스테이킹 기능이 없습니다.
3.  **인코딩**: 생성된 주소는 Bech32로 인코딩됩니다.

## Cosmos (ATOM)

코스모스 기반 체인들의 주소는 `cosmos`와 같은 HRP(Human-Readable Part)로 시작하며, Bech32 인코딩을 사용합니다.

1.  **키 생성**: 개인키로부터 공개키를 생성합니다.
2.  **해싱**: 공개키를 `SHA-256`으로 해싱한 후, 그 결과를 `RIPEMD-160`으로 다시 해싱합니다.
3.  **인코딩**: 해싱된 결과를 Bech32로 인코딩합니다. 이때 각 체인에 맞는 HRP를 사용합니다. (예: Cosmos Hub는 `cosmos`, Osmosis는 `osmo`)

## Solana (SOL)

솔라나 주소는 스텔라와 유사하게 공개키를 그대로 사용하지만, Base58로 인코딩한다는 차이점이 있습니다.

1.  **키 생성**: Ed25519 알고리즘을 사용하여 32바이트 길이의 개인키와 공개키 쌍을 생성합니다.
2.  **주소**: 생성된 32바이트 공개키가 솔라나 주소입니다.
3.  **인코딩**: 이 주소는 사용자에게 보여질 때 Base58로 인코딩되어 32~44자 사이의 문자열로 표현됩니다.

## Polkadot (DOT)

폴카닷 주소는 SS58이라는 독자적인 주소 형식을 사용합니다. 이는 네트워크마다 다른 주소 접두사를 부여하여 주소를 구분하는 것이 특징입니다.

1.  **키 생성**: 개인키로부터 32바이트의 공개키를 생성합니다.
2.  **주소 형식**: 공개키에 네트워크를 식별하는 접두사(Address Type) 바이트를 추가합니다. (예: 폴카닷은 `0`, 쿠사마는 `2`)
3.  **해싱**: 주소 형식과 공개키를 합친 데이터에 `BLAKE2b-512` 해시를 적용하여 체크섬을 생성합니다.
4.  **인코딩**: 주소 형식, 공개키, 체크섬의 일부를 모두 합친 후 Base58로 인코딩하여 최종 주소를 만듭니다.

## Dogecoin (DOGE)

도지코인 주소는 `D`로 시작하며, 비트코인의 P2PKH 주소 생성 방식과 거의 동일하지만 주소 버전 바이트가 다릅니다.

1.  **키 생성**: 개인키로부터 공개키를 생성합니다.
2.  **해싱**: 공개키를 `SHA-256`으로 해싱한 후, 그 결과를 `RIPEMD-160`으로 다시 해싱합니다.
3.  **버전 부여**: 해싱된 결과에 도지코인 메인넷을 나타내는 버전 바이트 `0x1E`를 앞에 붙입니다.
4.  **체크섬**: 버전이 부여된 해시를 두 번 `SHA-256` 해싱한 후, 결과의 첫 4바이트를 체크섬으로 사용합니다.
5.  **인코딩**: 버전이 부여된 해시와 체크섬을 합친 후, Base58Check로 인코딩합니다.

## Avalanche (AVAX)

아발란체는 여러 체인으로 구성되며, 각 체인은 다른 주소 형식을 사용합니다.

*   **X-Chain (Exchange Chain)**: 자산 생성 및 거래에 사용됩니다. `X-avax1`으로 시작하는 Bech32 인코딩 주소를 사용합니다.
*   **P-Chain (Platform Chain)**: 밸리데이터 및 서브넷 관리에 사용됩니다. `P-avax1`으로 시작하는 Bech32 인코딩 주소를 사용합니다.
*   **C-Chain (Contract Chain)**: 이더리움과 호환되는 스마트 컨트랙트 체인입니다. `0x`로 시작하는 이더리움 주소 형식을 그대로 사용합니다.

X-Chain과 P-Chain은 공개키를 해싱하고 Bech32로 인코딩하여 주소를 생성하며, C-Chain은 이더리움과 동일한 방식으로 Keccak-256 해시의 마지막 20바이트를 주소로 사용합니다.

## TRON (TRX)

TRON 주소는 `T`로 시작하며, 비트코인과 유사한 Base58Check 인코딩을 사용합니다.

1.  **키 생성**: secp256k1 곡선을 사용하여 개인키와 공개키(64바이트) 쌍을 생성합니다.
2.  **해싱**: 공개키를 `KECCAK-256`으로 해싱합니다.
3.  **마지막 20바이트 추출**: 해싱 결과의 마지막 20바이트를 추출합니다.
4.  **주소 접두사 추가**: 20바이트 결과 앞에 `0x41` 접두사 바이트를 추가하여 21바이트 초기 주소를 만듭니다.
5.  **체크섬 계산**: 21바이트 초기 주소를 두 번 `SHA-256` 해싱한 후, 그 결과의 첫 4바이트를 체크섬으로 사용합니다.
6.  **Base58Check 인코딩**: 21바이트 초기 주소와 4바이트 체크섬을 결합한 후, Base58Check 인코딩을 적용하여 최종 주소를 생성합니다.

## Tezos (XTZ)

Tezos 주소는 `tz`로 시작하며, 사용된 암호화 곡선에 따라 접두사가 달라집니다.

1.  **키 생성**: 개인키로부터 공개키를 생성합니다.
2.  **공개키 해싱**: 공개키를 해싱 알고리즘(주로 Blake2b)을 사용하여 해싱합니다.
3.  **Base58Check 인코딩**: 해싱된 결과에 주소 유형(예: `tz1`, `tz2`, `tz3`)을 나타내는 접두사를 붙인 후, Base58Check 인코딩을 적용하여 최종 주소를 생성합니다.
    *   `tz1`: Ed25519 공개키
    *   `tz2`: Secp256k1 공개키
    *   `tz3`: P-256 공개키

## Monero (XMR)

모네로 주소는 프라이버시에 중점을 두며, 두 개의 공개키를 기반으로 생성되는 독특한 시스템을 가집니다. 일반적인 주소는 `4`로 시작하며 95자 길이입니다.

1.  **키 쌍**: 모네로 지갑은 두 쌍의 키를 가집니다.
    *   **지출 키 (Spend Key)**: 거래 승인에 사용되는 개인 지출 키와 주소의 일부가 되는 공개 지출 키.
    *   **뷰 키 (View Key)**: 수신 거래를 스캔하는 데 사용되는 개인 뷰 키와 주소의 일부가 되는 공개 뷰 키.
2.  **주소 구성**:
    *   **네트워크 바이트**: 네트워크 및 주소 유형을 식별하는 바이트(예: 메인넷의 경우 `18`).
    *   **공개 지출 키**: 32바이트.
    *   **공개 뷰 키**: 32바이트.
    위 세 가지를 순서대로 연결합니다. (총 1 + 32 + 32 = 65바이트)
3.  **체크섬 계산**: 연결된 65바이트 데이터에 `Keccak-256` 해시를 적용하고, 결과 해시의 첫 4바이트를 체크섬으로 사용합니다.
4.  **Base58 인코딩**: 65바이트 데이터와 4바이트 체크섬을 결합(총 69바이트)한 후, 모네로 고유의 Base58 인코딩을 적용하여 95자의 최종 주소를 생성합니다.
