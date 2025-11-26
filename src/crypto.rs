use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::convert::TryInto;
use std::error::Error;
use std::fs::File;
use std::io::Write;

pub struct DhKeyPair {
    pub secret: BigUint,
    pub public: BigUint,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HandshakeMessage {
    pub role: String,
    /// Ephemeral DH public key encoded為十進位的大整數字串
    pub ephemeral_public_dec: String,
    pub signature_b64: String,
    pub signing_public_b64: String,
}

/// Parse decimal string to BigUint or panic.
fn parse_dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).expect("invalid decimal number")
}

/// Rejection sampling: uniform integer in [1, q-1]
fn gen_privkey_uniform(q: &BigUint) -> BigUint {
    assert!(q > &BigUint::one(), "q must be > 1");
    let upper = q - BigUint::one(); // q-1
    let mut rng = OsRng;

    loop {
        // generate random in [0, upper] uniformly by using RandBigInt::gen_biguint_below
        // but gen_biguint_below returns in [0, upper), so use upper + 1
        let candidate = rng.gen_biguint_below(&(upper.clone() + BigUint::one()));
        // candidate ∈ [0, upper]
        if candidate.is_zero() {
            continue; // reject 0, we need >=1
        }
        // candidate in [1, upper] -> valid
        return candidate;
    }
}

/// Find a generator g of the subgroup of order q (i.e. g^q ≡ 1 mod p and g != 1).
/// We compute exp = (p - 1) / q and test h = 2,3,... until g = h^exp mod p != 1.
fn find_generator(p: &BigUint, q: &BigUint) -> BigUint {
    let one = BigUint::one();
    let exp = (p - &one) / q;

    let mut h = BigUint::from(2u32);
    for _ in 0..10_000u32 {
        let g = h.modpow(&exp, p);
        if g != one {
            return g;
        }
        h += &one;
    }

    panic!("failed to find generator g in 10000 attempts; consider providing g explicitly");
}

fn dh_params() -> (BigUint, BigUint, BigUint) {
    // 這裡直接嵌入你提供的 p 和 q（十進位字串）
    let p_dec = "28766814515305344925135327846265618912664117797851731587904878015462803249977235941249703516789944091749898600299383135916258394165277154746850690924885409374613186677403293002561212823872134794612885736588353062665100257458192024578240831157340603512117881798371957928710301007355966949768954314381974229634562328230946414283068159460377595218094419073047560165707147374992696155554785175464279458669266476082782086850251603744388440411967541655962957589131628215119151589278605243618074656948031279999629258824412353704611067503482710930591891408577064246882098497237368756242458991599578221980723033002346183986743";
    let q_dec = "14383407257652672462567663923132809456332058898925865793952439007731401624988617970624851758394972045874949300149691567958129197082638577373425345462442704687306593338701646501280606411936067397306442868294176531332550128729096012289120415578670301756058940899185978964355150503677983474884477157190987114817281164115473207141534079730188797609047209536523780082853573687496348077777392587732139729334633238041391043425125801872194220205983770827981478794565814107559575794639302621809037328474015639999814629412206176852305533751741355465295945704288532123441049248618684378121229495799789110990361516501173091993371";

    let p = parse_dec(p_dec);
    let q = parse_dec(q_dec);
    let g = find_generator(&p, &q);
    (p, q, g)
}

pub fn generate_dh_keypair() -> DhKeyPair {
    let (p, q, g) = dh_params();
    let x = gen_privkey_uniform(&q);
    let public = g.modpow(&x, &p);
    DhKeyPair { secret: x, public }
}

pub fn sign_ephemeral(signing: &SigningKey, ephemeral_public_dec: &str) -> Signature {
    signing.sign(ephemeral_public_dec.as_bytes())
}

pub fn verify_ephemeral_signature(
    verifying: &VerifyingKey,
    ephemeral_public_dec: &str,
    signature: &Signature,
) -> Result<(), ed25519_dalek::SignatureError> {
    verifying.verify(ephemeral_public_dec.as_bytes(), signature)
}

pub fn compute_shared_secret(
    my_secret: &BigUint,
    their_public: &BigUint,
) -> BigUint {
    let (p, _q, _g) = dh_params();
    their_public.modpow(my_secret, &p)
}

pub fn encode_b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn decode_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(s)
}

/// 使用 HKDF-SHA256 從共享的大整數秘密推導出 32 bytes AES-256 key。
pub fn derive_aes256_key(shared: &BigUint) -> [u8; 32] {
    let ikm = shared.to_bytes_be();
    let salt = b"full-DH-with-sign hkdf salt";
    let info = b"dh-shared-to-aes-256";
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand for AES-256 key should not fail");
    okm
}

// 以前為 X25519 寫的 bytes <-> decimal 轉換不再需要，
// 因為現在直接用 BigUint 的十進位表示。

pub fn handshake_message_from_parts(
    role: &str,
    eph_public_dec: &str,
    signature: &Signature,
    verifying: &VerifyingKey,
) -> HandshakeMessage {
    HandshakeMessage {
        role: role.to_owned(),
        ephemeral_public_dec: eph_public_dec.to_owned(),
        signature_b64: encode_b64(&signature.to_bytes()),
        signing_public_b64: encode_b64(verifying.as_bytes()),
    }
}

pub fn parse_handshake_message(
    msg: &HandshakeMessage,
) -> Result<(BigUint, Signature, VerifyingKey), String> {
    let eph_pub = BigUint::parse_bytes(msg.ephemeral_public_dec.as_bytes(), 10)
        .ok_or_else(|| "invalid decimal for ephemeral_public_dec".to_string())?;
    let sig_bytes = decode_b64(&msg.signature_b64)
        .map_err(|e| format!("decode signature_b64: {e}"))?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| format!("parse signature: {e}"))?;

    let pk_bytes = decode_b64(&msg.signing_public_b64)
        .map_err(|e| format!("decode signing_public_b64: {e}"))?;
    if pk_bytes.len() != 32 {
        return Err("signing public key length must be 32 bytes".into());
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let verifying = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| format!("parse signing public key: {e}"))?;

    Ok((eph_pub, signature, verifying))
}

fn write_binary(path: &str, data: &[u8]) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(data)?;
    Ok(())
}

pub fn generate_and_save_signing_key_pair_with_prefix(
    prefix: &str,
) -> Result<(), Box<dyn Error>> {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // 用固定訊息測試一次簽名與驗證
    let message = b"hello Ed25519!";
    let signature: Signature = signing_key.sign(message);
    verifying_key
        .verify(message, &signature)
        .expect("signature verification failed");

    // 匯出位元組
    let sk_bytes = signing_key.to_bytes(); // 32 bytes
    let pk_bytes = verifying_key.to_bytes(); // 32 bytes
    let sig_bytes = signature.to_bytes(); // 64 bytes

    // 寫入二進位檔案（以角色前綴 alice_/bob_ 開頭）
    write_binary(&format!("{prefix}_ed25519_secret.key"), &sk_bytes)?;
    write_binary(&format!("{prefix}_ed25519_public.key"), &pk_bytes)?;

    // Base64 編碼，並寫到一個文字檔方便查看與複製
    let sk_b64 = encode_b64(&sk_bytes);
    let pk_b64 = encode_b64(&pk_bytes);
    let sig_b64 = encode_b64(&sig_bytes);

    let mut f = File::create(format!("{prefix}_ed25519_keys_base64.txt"))?;
    writeln!(f, "Public key  (Base64): {pk_b64}")?;
    writeln!(f, "Secret key  (Base64): {sk_b64}")?;
    writeln!(f, "Signature   (Base64): {sig_b64}")?;

    println!("Ed25519 keys generated for prefix `{prefix}`.");
    println!("  Binary secret key: {prefix}_ed25519_secret.key");
    println!("  Binary public key: {prefix}_ed25519_public.key");
    println!("  Base64 text file : {prefix}_ed25519_keys_base64.txt");

    Ok(())
}

#[derive(Clone)]
pub struct LongTermSigning {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
    pub sk_b64: String,
    pub pk_b64: String,
}

/// 從本地檔案載入長期簽名金鑰，並同時回傳 Base64 形式方便在網頁上顯示。
pub fn load_longterm_signing(prefix: &str) -> Result<LongTermSigning, Box<dyn Error>> {
    let sk_path = format!("{prefix}_ed25519_secret.key");
    let sk_bytes = std::fs::read(&sk_path)?;
    if sk_bytes.len() != 32 {
        return Err(format!(
            "secret key file `{}` must be 32 bytes, got {} bytes",
            sk_path,
            sk_bytes.len()
        )
        .into());
    }

    let sk_array: [u8; 32] = sk_bytes
        .as_slice()
        .try_into()
        .expect("slice with incorrect length");
    let signing = SigningKey::from_bytes(&sk_array);
    let verifying = signing.verifying_key();

    let sk_b64 = encode_b64(&sk_bytes);
    let pk_b64 = encode_b64(&verifying.to_bytes());

    Ok(LongTermSigning {
        signing,
        verifying,
        sk_b64,
        pk_b64,
    })
}
