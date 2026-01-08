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

## BNB Smart Chain (BSC)

BNB Smart Chain (BSC)은 이더리움 가상 머신(EVM)과 호환되는 블록체인이므로, 주소 생성 방식은 이더리움과 동일합니다.

1.  **공개키 추출**: 개인키로부터 `secp256k1` 곡선을 사용하여 압축되지 않은 64바이트 공개키를 추출합니다.
2.  **해싱**: 64바이트 공개키를 `KECCAK-256` 해싱 함수에 적용합니다.
3.  **마지막 20바이트 추출**: `KECCAK-256` 해시 결과의 마지막 20바이트(40 16진수 문자)를 가져옵니다.
4.  **`0x` 접두사 추가**: 20바이트 16진수 문자열 앞에 `0x` 접두사를 붙여 최종 42자 BSC 주소를 형성합니다.

## Litecoin (LTC)

라이트코인 주소는 비트코인과 유사한 주소 생성 방식을 따르지만, 주소 접두사에 차이가 있습니다.

*   **Legacy (P2PKH)**: `L`로 시작하는 주소입니다. 비트코인의 P2PKH와 동일한 절차를 따르지만, 버전 바이트로 `0x30`을 사용합니다.
*   **SegWit (P2SH)**: `M`으로 시작하는 주소입니다. 비트코인의 P2SH와 유사하며, 버전 바이트로 `0x32`를 사용합니다.
*   **Native SegWit (Bech32)**: `ltc1`으로 시작하는 주소입니다. 비트코인의 Bech32와 동일한 구조를 가집니다.

## Bitcoin Cash (BCH)

비트코인 캐시는 비트코인 주소와의 혼동을 피하기 위해 CashAddr라는 독자적인 주소 형식을 사용합니다.

1.  **공개키 해싱**: 공개키를 `SHA-256`과 `RIPEMD-160`으로 해싱하여 20바이트의 공개키 해시를 생성합니다.
2.  **CashAddr 인코딩**:
    *   **접두사**: `bitcoincash:` 라는 접두사가 붙습니다.
    *   **버전 바이트**: 주소 유형 및 네트워크를 나타내는 버전 바이트를 추가합니다.
    *   **인코딩**: 공개키 해시, 버전 바이트 및 접두사를 Base32로 인코딩하여 최종 주소를 생성합니다. 이 과정에는 오류 감지를 위한 40비트 체크섬이 포함됩니다.

## Zcash (ZEC)

Zcash는 프라이버시를 위해 투명 주소와 차폐 주소 두 가지 유형을 사용합니다.

*   **투명 주소 (Transparent Address, t-addr)**:
    *   `t`로 시작하며, 비트코인 주소와 생성 방식이 거의 동일합니다.
    *   공개키를 해싱하고, 버전 접두사(예: P2PKH의 경우 `0x1CB8`)를 붙인 후 Base58Check로 인코딩합니다.
    *   거래 내역이 공개적으로 블록체인에 기록됩니다.

*   **차폐 주소 (Shielded Address, z-addr)**:
    *   `z`로 시작하며, 영지식 증명(zk-SNARKs)을 사용하여 거래의 발신자, 수신자, 금액을 숨깁니다.
    *   생성 과정이 복잡하며, 지불 키(spending key)와 뷰 키(viewing key) 등 여러 키를 포함하는 '지불 주소(Payment Address)'로부터 파생됩니다.

## Chainlink (LINK)

Chainlink (LINK)는 이더리움 블록체인 위에서 발행된 ERC-20 토큰입니다. 따라서 Chainlink는 독자적인 블록체인이나 주소 체계를 가지고 있지 않으며, LINK 토큰을 보관하고 전송하기 위해 **이더리움 주소**를 사용합니다.

즉, LINK 토큰의 주소는 이더리움 주소와 동일하며, 생성 방식 또한 이더리움의 주소 생성 방식과 같습니다. 이는 다른 모든 ERC-20 토큰 및 EVM 호환 체인의 토큰들도 마찬가지입니다.

## Polygon (MATIC)

Polygon (MATIC)은 이더리움과 호환되는 EVM(Ethereum Virtual Machine) 기반 블록체인이므로, 주소 생성 방식은 이더리움과 동일합니다.

1.  **공개키 추출**: 개인키로부터 `secp256k1` 곡선을 사용하여 압축되지 않은 64바이트 공개키를 추출합니다.
2.  **Keccak-256 해싱**: 64바이트 공개키를 `Keccak-256` 해싱 함수에 적용합니다. 이때 공개키의 앞에 붙는 `0x04` 접두사는 제거합니다.
3.  **마지막 20바이트 추출**: `Keccak-256` 해시 결과의 마지막 20바이트(40 16진수 문자)를 가져옵니다.
4.  **`0x` 접두사 추가**: 20바이트 16진수 문자열 앞에 `0x` 접두사를 붙여 최종 42자 Polygon 주소를 형성합니다.

## Binance Coin (BNB) (BEP2)

BNB Beacon Chain (이전 Binance Chain)의 BNB (BEP2) 주소는 `bnb`로 시작하며, 코스모스 SDK 기반의 주소 생성 방식을 따릅니다.

1.  **공개키 추출**: 개인키로부터 공개키를 추출합니다.
2.  **공개키 해싱**: 공개키를 `SHA-256`으로 해싱한 후, 그 결과를 `RIPEMD-160`으로 다시 해싱하여 20바이트의 해시를 생성합니다.
3.  **Bech32 인코딩**: 20바이트 해시를 Bech32로 인코딩합니다. 이때 Human-Readable Part (HRP)로 "bnb"를 사용합니다.

## VeChain (VET)

VeChain (VET) 주소는 이더리움 주소와 동일한 `0x` 접두사 형식을 가지며, `Secp256k1` 공개키 암호화를 사용합니다.

1.  **공개키 추출**: 개인키로부터 `Secp256k1` 공개키를 추출합니다.
2.  **Keccak-256 해싱**: 추출된 공개키를 `Keccak-256` 해싱 함수에 적용합니다.
3.  **마지막 20바이트 추출**: `Keccak-256` 해시 결과의 마지막 20바이트를 가져옵니다.
4.  **`0x` 접두사 추가**: 20바이트 결과 앞에 `0x` 접두사를 붙여 최종 42자 VeChain 주소를 형성합니다.

## NEAR Protocol (NEAR)

NEAR 프로토콜은 두 가지 종류의 계정 주소를 사용합니다.

*   **명시적 계정 (Named Account)**: `alice.near`와 같이 사람이 읽을 수 있는 주소입니다. 하나의 명시적 계정은 여러 키를 가질 수 있어, 키 관리에 유연성을 제공합니다.
*   **암시적 계정 (Implicit Account)**:
    *   `Ed25519` 공개키로부터 직접 생성되며, 64자의 16진수 문자열로 표현됩니다.
    *   공개키를 그대로 16진수 문자열로 변환하여 주소로 사용하므로, 별도의 온체인 생성 절차가 필요 없습니다.

## Internet Computer (ICP)

Internet Computer의 주소는 **Principal ID** 라고 불리며, 사용자와 캐니스터(스마트 컨트랙트)를 식별하는 데 사용됩니다.

1.  **키 생성**: 개인키/공개키 쌍을 생성합니다.
2.  **Principal ID 생성**: 공개키로부터 직접 Principal ID가 파생됩니다.
3.  **계정 ID (Account ID)**: Principal ID와 선택적 서브 계정 번호를 조합하여 ICP 원장에서 사용되는 계정 ID를 생성합니다. 이는 개인 정보 보호를 강화하는 데 도움이 됩니다.

## Fantom (FTM)

Fantom (FTM)은 이더리움 가상 머신(EVM)과 호환되는 블록체인이므로, 주소 생성 방식은 이더리움과 동일합니다.

1.  **공개키 추출**: 개인키로부터 `secp256k1` 곡선을 사용하여 압축되지 않은 64바이트 공개키를 추출합니다.
2.  **Keccak-256 해싱**: 64바이트 공개키를 `Keccak-256` 해싱 함수에 적용합니다.
3.  **마지막 20바이트 추출**: `Keccak-256` 해시 결과의 마지막 20바이트를 가져옵니다.
4.  **`0x` 접두사 추가**: 20바이트 결과 앞에 `0x` 접두사를 붙여 최종 42자 Fantom 주소를 형성합니다.

## Hedera (HBAR)

Hedera의 주소는 `shard.realm.num` (예: `0.0.12345`) 형태의 숫자 계정 ID를 사용합니다. 공개키로부터 직접 주소를 "생성"하기보다는, 공개키를 "계정 별칭"으로 사용하여 계정을 자동으로 생성하는 독특한 방식을 사용합니다.

1.  **키 생성**: `ED25519` 또는 `ECDSA(secp256k1)` 키 쌍을 생성합니다.
2.  **계정 별칭 사용**: 공개키를 `0.0.<publicKey>` 형식의 별칭으로 사용합니다.
3.  **자동 계정 생성**: 이 별칭으로 첫 거래가 발생하면, 헤데라 네트워크는 해당 공개키와 연결된 새로운 숫자 계정 ID를 자동으로 생성하고 할당합니다.

## Algorand (ALGO)

Algorand 주소는 58자 길이의 문자열로, `Ed25519` 공개키로부터 생성됩니다.

1.  **키 생성**: `Ed25519` 알고리즘을 사용하여 32바이트의 개인키와 32바이트의 공개키 쌍을 생성합니다.
2.  **체크섬 추가**: 32바이트 공개키에 4바이트의 체크섬을 추가하여 36바이트 데이터를 만듭니다.
3.  **Base32 인코딩**: 36바이트 데이터를 Base32로 인코딩하여 58자의 최종 주소를 생성합니다.

## EOS (EOS)

EOS는 주소 대신 **계정 이름(Account Name)**을 사용합니다. 이 계정 이름은 사람이 읽을 수 있는 12자리 문자열로, 공개키와 매핑되어 사용자의 신원을 나타냅니다.

1.  **키 쌍 생성**: 개인키와 공개키 쌍을 생성합니다.
2.  **계정 이름 생성**: 블록체인 상에서 고유한 12자리 계정 이름을 생성합니다. 이 과정은 이미 존재하는 계정의 도움이 필요하며, 리소스를 지불해야 합니다.
3.  **키와 계정 매핑**: 생성된 계정 이름에 소유자(owner) 키와 활성(active) 키로 사용할 공개키를 할당합니다.

## Flow (FLOW)

Flow 주소는 공개키로부터 직접 파생되지 않으며, 프로토콜에 의해 결정론적으로 순차 할당되는 고유 식별자입니다.

*   **주소 할당**: 계정이 생성될 때 Flow 프로토콜이 주소를 할당합니다.
*   **다중 키 지원**: 하나의 Flow 계정은 여러 개의 공개키를 가질 수 있으며, 각 키는 다른 가중치를 가질 수 있습니다. 이는 계정 복구 및 보안 강화에 유용합니다.
*   **유연성**: 하나의 공개키가 여러 Flow 계정에서 사용될 수도 있습니다.

## Aptos (APT)

Aptos 주소는 32바이트의 계정 식별자로, `0x` 접두사를 붙인 16진수 문자열로 표현됩니다.

1.  **키 생성**: `Ed25519` 키 쌍을 생성합니다.
2.  **인증 키 생성**: 32바이트 공개키에 1바이트의 서명 방식 식별자 (`0x00` for `Ed25519`)를 추가합니다.
3.  **해싱**: 위에서 생성된 33바이트 데이터에 `SHA3-256` 해시를 적용합니다.
4.  **주소 할당**: 해시 결과인 32바이트가 계정의 영구적인 주소가 됩니다. Aptos는 키 순환(key rotation)을 지원하므로, 계정 주소는 변경되지 않은 채로 계정과 연결된 실제 키는 변경될 수 있습니다.

## Sui (SUI)

Sui 주소는 공개키와 서명 방식을 나타내는 1바이트 플래그를 결합하여 생성됩니다.

1.  **키 생성**: `Ed25519`, `Secp256k1`, `Secp256r1` 등의 키 쌍을 생성합니다.
2.  **플래그 추가**: 공개키 앞에 해당 키의 서명 방식을 나타내는 1바이트 플래그를 추가합니다. (예: `Ed25519`는 `0x00`)
3.  **해싱**: 플래그와 공개키를 합친 데이터에 `BLAKE2b` 해시 함수를 적용하여 32바이트의 해시를 생성합니다.
4.  **주소**: 이 32바이트 해시가 Sui 주소가 되며, 일반적으로 `0x` 접두사를 붙인 16진수 문자열로 표현됩니다.

## Sei (SEI)

Sei는 코스모스 SDK와 EVM 호환성을 모두 제공하는 독특한 이중 주소 시스템을 가지고 있습니다. 동일한 공개키로부터 두 가지 형식의 주소가 파생됩니다.

1.  **공개키 해싱**: 공개키에 `keccak256` 해싱 알고리즘을 적용합니다.
2.  **주소 파생**:
    *   **코스모스 주소**: 해시 결과의 **첫 20바이트**를 `sei` 접두사를 사용하여 Bech32로 인코딩합니다. (예: `sei1...`)
    *   **EVM 주소**: 해시 결과의 **마지막 20바이트**에 `0x` 접두사를 붙입니다. (예: `0x...`)

이 두 주소는 서로 다른 형식이지만, 동일한 기본 계정을 가리킵니다.

## Stacks (STX)

Stacks 주소는 비트코인 주소와 유사한 생성 방식을 가지지만, `c32check`라는 자체 인코딩 방식을 사용합니다.

1.  **키 생성**: `secp256k1` 키 쌍을 생성합니다.
2.  **공개키 해싱**: 공개키에 `SHA256` 해싱을 적용한 후, 그 결과에 `RIPEMD-160` 해싱을 적용합니다.
3.  **버전 바이트 추가**: 해싱된 결과 앞에 네트워크(메인넷, 테스트넷)를 구분하는 버전 바이트를 추가합니다.
4.  **c32check 인코딩**: 버전 바이트가 추가된 데이터를 `c32check` 방식으로 인코딩하여 최종 주소를 생성합니다. Stacks 메인넷 주소는 `S`로 시작합니다.

## Filecoin (FIL)

Filecoin 주소는 네트워크 접두사와 프로토콜 표시기를 사용하여 다양한 주소 유형을 지원합니다.

*   **네트워크 접두사**: `f` (메인넷) 또는 `t` (테스트넷)로 시작합니다.
*   **프로토콜 표시기**:
    *   **`1` (SECP256k1 주소)**:
        1.  공개키를 `BLAKE2b-160`으로 해싱하여 페이로드를 생성합니다.
        2.  `1` 표시기, 페이로드, 체크섬을 결합하여 Base32로 인코딩합니다.
    *   **`3` (BLS 주소)**:
        1.  BLS 공개키 자체가 페이로드가 됩니다.
        2.  `3` 표시기, 페이로드, 체크섬을 결합하여 Base32로 인코딩합니다.

## Arweave (AR)

Arweave 주소는 `RSA-PSS` 키 쌍의 공개키(`n` 값)로부터 생성됩니다.

1.  **키 생성**: 4096비트 `RSA-PSS` 키 쌍을 생성합니다.
2.  **공개키 해싱**: 공개키의 `n` 값(공개 모듈러스)을 `SHA-256`으로 해싱합니다.
3.  **Base64URL 인코딩**: 해싱된 결과를 Base64URL로 인코딩하여 43자의 최종 주소를 생성합니다.

## Kaspa (KAS)

Kaspa 주소는 `kaspa:` 접두사로 시작하며, Bech32 인코딩을 사용합니다.

1.  **키 생성**: `secp256k1` 키 쌍을 생성합니다.
2.  **주소 구성요소**: 네트워크 유형, 공개키 유형, 그리고 공개키 자체를 결합합니다.
3.  **Bech32 인코딩**: 구성요소들을 Bech32로 인코딩하여 최종 주소를 생성합니다.

## Render Token (RNDR)

Render Token (RNDR)은 이더리움 블록체인 위에서 발행된 ERC-20 토큰입니다. 따라서 RNDR은 독자적인 블록체인이나 주소 체계를 가지고 있지 않으며, 토큰을 보관하고 전송하기 위해 **이더리움 주소**를 사용합니다.

이는 다른 모든 ERC-20 토큰 및 EVM 호환 체인의 토큰들과 마찬가지로, 이더리움의 주소 생성 방식과 동일합니다.

## Theta Network (THETA)

Theta Network는 비디오 스트리밍을 위한 블록체인으로, 이더리움과 호환되는 주소 체계를 사용합니다. 따라서 주소 생성 방식은 이더리움과 동일합니다.

1.  **공개키 추출**: 개인키로부터 `secp256k1` 곡선을 사용하여 압축되지 않은 64바이트 공개키를 추출합니다.
2.  **Keccak-256 해싱**: 64바이트 공개키를 `Keccak-256` 해싱 함수에 적용합니다.
3.  **마지막 20바이트 추출**: `Keccak-256` 해시 결과의 마지막 20바이트를 가져옵니다.
4.  **`0x` 접두사 추가**: 20바이트 결과 앞에 `0x` 접두사를 붙여 최종 42자 Theta 주소를 형성합니다.

## Optimism (OP) & Arbitrum (ARB)

Optimism과 Arbitrum은 이더리움의 레이어 2 확장 솔루션으로, EVM과 완벽하게 호환됩니다. 따라서 두 네트워크 모두 주소 생성 방식이 이더리움과 동일합니다.

사용자는 동일한 이더리움 주소와 개인키를 사용하여 Optimism과 Arbitrum 네트워크와 상호작용할 수 있습니다. 이는 개발자와 사용자 모두에게 편리함을 제공하며, 이더리움 생태계 내에서 자산을 쉽게 이동하고 관리할 수 있게 합니다.
