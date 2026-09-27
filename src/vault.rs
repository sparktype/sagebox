// 비밀과 프로필을 Argon2id + XChaCha20-Poly1305로 암호화해 파일로 저장하는 볼트
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub type Key = Zeroizing<[u8; 32]>;

const MAGIC: &[u8; 4] = b"SBX1";
/// MAGIC | salt(16) | m | t | p — 전부 AAD로 인증된다.
const HEADER_LEN: usize = 4 + 16 + 12;
const NONCE_LEN: usize = 24;

#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    #[serde(default)]
    pub secrets: BTreeMap<String, Zeroizing<String>>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Profile {
    pub command: Vec<String>,
    /// 환경변수 이름 → 비밀 이름
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    salt: [u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Header {
    /// 새 볼트용 헤더. Argon2id m=64MiB, t=3, p=1.
    pub fn new() -> Result<Self> {
        Self::with_params(64 * 1024, 3, 1)
    }

    pub fn with_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt)?;
        Ok(Header {
            salt,
            m_cost,
            t_cost,
            p_cost,
        })
    }

    pub fn parse(file: &[u8]) -> Result<Self> {
        if file.len() < HEADER_LEN + NONCE_LEN || &file[..4] != MAGIC {
            return Err("not a secretbox vault".into());
        }
        let u32_at = |i: usize| u32::from_le_bytes(file[i..i + 4].try_into().unwrap());
        Ok(Header {
            salt: file[4..20].try_into().unwrap(),
            m_cost: u32_at(20),
            t_cost: u32_at(24),
            p_cost: u32_at(28),
        })
    }

    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[..4].copy_from_slice(MAGIC);
        h[4..20].copy_from_slice(&self.salt);
        h[20..24].copy_from_slice(&self.m_cost.to_le_bytes());
        h[24..28].copy_from_slice(&self.t_cost.to_le_bytes());
        h[28..32].copy_from_slice(&self.p_cost.to_le_bytes());
        h
    }

    pub fn derive_key(&self, passphrase: &[u8]) -> Result<Key> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))?;
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(
            passphrase,
            &self.salt,
            key.as_mut(),
        )?;
        Ok(key)
    }
}

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new((&**key).into())
}

pub fn seal(vault: &Vault, header: &Header, key: &Key) -> Result<Vec<u8>> {
    let aad = header.encode();
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)?;
    // ponytail: Vec 재할당 시 이전 버퍼에 평문 조각이 남을 수 있음. 문제되면 크기 예측 후 with_capacity로 한 번에 할당
    let plain = Zeroizing::new(serde_json::to_vec(vault)?);
    let ct = cipher(key)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .map_err(|_| "encryption failed")?;
    Ok([&aad[..], &nonce, &ct].concat())
}

/// 헤더를 파싱하고 key로 복호화한다. 패스프레이즈가 틀렸거나 파일이 변조되면 Err.
pub fn open(file: &[u8], key: &Key) -> Result<Vault> {
    Header::parse(file)?;
    let (aad, rest) = file.split_at(HEADER_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let nonce = XNonce::from(<[u8; NONCE_LEN]>::try_from(nonce).unwrap());
    let plain = Zeroizing::new(
        cipher(key)
            .decrypt(&nonce, Payload { msg: ct, aad })
            .map_err(|_| "wrong passphrase or corrupted vault")?,
    );
    Ok(serde_json::from_slice(&plain)?)
}

/// 같은 디렉터리의 임시 파일(0600)에 쓰고 rename해 원자적으로 교체한다.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 테스트는 가벼운 KDF 파라미터로 속도를 확보한다.
    fn fixture() -> (Header, Key, Vault) {
        let h = Header::with_params(64, 1, 1).unwrap();
        let key = h.derive_key(b"correct horse").unwrap();
        let mut v = Vault::default();
        v.secrets
            .insert("gh".into(), Zeroizing::new("ghp_123".into()));
        v.profiles.insert(
            "github".into(),
            Profile {
                command: vec!["/usr/bin/env".into()],
                env: [("GITHUB_TOKEN".into(), "gh".into())].into(),
            },
        );
        (h, key, v)
    }

    #[test]
    fn roundtrip() {
        let (h, key, v) = fixture();
        let file = seal(&v, &h, &key).unwrap();
        assert_eq!(Header::parse(&file).unwrap(), h);
        let back = open(&file, &key).unwrap();
        assert_eq!(back.secrets["gh"].as_str(), "ghp_123");
        assert_eq!(back.profiles, v.profiles);
        assert!(
            !file.windows(7).any(|w| w == b"ghp_123"),
            "plaintext leaked"
        );
    }

    #[test]
    fn same_header_yields_same_key_and_fresh_nonce() {
        let (h, key, v) = fixture();
        let reparsed = Header::parse(&seal(&v, &h, &key).unwrap()).unwrap();
        assert_eq!(*reparsed.derive_key(b"correct horse").unwrap(), *key);
        assert_ne!(seal(&v, &h, &key).unwrap(), seal(&v, &h, &key).unwrap());
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let (h, key, v) = fixture();
        let file = seal(&v, &h, &key).unwrap();
        assert!(open(&file, &h.derive_key(b"wrong").unwrap()).is_err());
    }

    #[test]
    fn tampering_rejected() {
        let (h, key, v) = fixture();
        let file = seal(&v, &h, &key).unwrap();
        for i in [0, 5, 22, HEADER_LEN + 1, file.len() - 1] {
            let mut bad = file.clone();
            bad[i] ^= 1;
            assert!(open(&bad, &key).is_err(), "byte {i} tamper accepted");
        }
        assert!(open(&file[..10], &key).is_err());
    }

    #[test]
    fn atomic_write_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sbx-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("vault");
        write_atomic(&p, b"a").unwrap();
        write_atomic(&p, b"b").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"b");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
