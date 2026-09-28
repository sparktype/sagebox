// 비밀과 프로필을 봉투 암호화(무작위 DEK + 키 슬롯)로 저장하는 볼트 파일 형식
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
/// 볼트 본문을 암호화하는 데이터 키. 데몬은 세션 동안 이것만 보관한다.
pub type Dek = Zeroizing<[u8; 32]>;

const MAGIC: &[u8; 4] = b"SBX2";
const VERSION: u32 = 2;
const NONCE_LEN: usize = 24;
/// Argon2id [m_cost(KiB), t_cost, p_cost]
pub const DEFAULT_KDF: [u32; 3] = [64 * 1024, 3, 1];
const PASSPHRASE: &str = "passphrase";

#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    #[serde(default)]
    pub secrets: BTreeMap<String, Zeroizing<String>>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    /// 비밀 이름 → 만료일 `YYYY-MM-DD`(UTC). 없던 필드라 기존 볼트도 그대로 읽힌다.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub expires: BTreeMap<String, String>,
    /// .sagevault 파일로 이 네임스페이스를 고를 수 있는 프로젝트 디렉터리(정규화 경로).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub trusted: BTreeSet<String>,
    /// `sgv env`가 셸(direnv)로 내보낼 환경변수 → 비밀 이름. `sgv import-env`가 채운다.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub shell_env: BTreeMap<String, String>,
}

impl Vault {
    /// 저장소 파일이 고른 요청이면 그 프로젝트가 신뢰 등록돼 있어야 한다. 데몬(Unix 전용)만 쓴다.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn check_project(&self, project: Option<&str>) -> Result<()> {
        match project {
            Some(dir) if !self.trusted.contains(dir) => Err(format!(
                "project {dir} is not trusted for this namespace; run `sgv trust` there (needs the namespace passphrase)"
            )
            .into()),
            _ => Ok(()),
        }
    }

    /// names 중 now(Unix 초) 기준으로 만료된 비밀이 있으면 Err.
    pub fn check_expiry<'a>(
        &self,
        names: impl IntoIterator<Item = &'a String>,
        now: i64,
    ) -> Result<()> {
        for name in names {
            if let Some(date) = self.expires.get(name)
                && parse_date(date)? <= now
            {
                return Err(format!("secret {name} expired on {date}").into());
            }
        }
        Ok(())
    }
}

/// `YYYY-MM-DD`를 그날 00:00 UTC의 Unix 초로 바꾼다. 그 시각부터 만료로 본다.
pub fn parse_date(s: &str) -> Result<i64> {
    let bad = || format!("invalid date {s:?} (expected YYYY-MM-DD)");
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return Err(bad().into());
    }
    let num = |r: std::ops::Range<usize>| s[r].parse::<i64>().map_err(|_| bad());
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    if !(1..=12).contains(&m) || d < 1 || d > days_from_civil(ny, nm, 1) - days_from_civil(y, m, 1)
    {
        return Err(bad().into());
    }
    Ok(days_from_civil(y, m, d) * 86_400)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// 1970-01-01부터의 일수 (Howard Hinnant의 days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Profile {
    pub command: Vec<String>,
    /// 환경변수 이름 → 비밀 이름
    pub env: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Header {
    version: u32,
    slots: Vec<Slot>,
}

/// DEK를 KEK로 감싼 것. `kind`마다 KEK를 얻는 방법만 다르고, 모르는 kind는 그대로 보존된다.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Slot {
    kind: String,
    params: serde_json::Value,
    nonce: [u8; NONCE_LEN],
    wrapped: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PassphraseParams {
    salt: [u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b)?;
    Ok(b)
}

fn aead_seal(key: &[u8; 32], msg: &[u8], aad: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = random::<NONCE_LEN>()?;
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(&XNonce::from(nonce), Payload { msg, aad })
        .map_err(|_| "encryption failed")?;
    Ok((nonce, ct))
}

fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ct: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let plain = XChaCha20Poly1305::new(key.into())
        .decrypt(&XNonce::from(*nonce), Payload { msg: ct, aad })
        .map_err(|_| "decryption failed: wrong key or corrupted vault")?;
    Ok(Zeroizing::new(plain))
}

impl Slot {
    /// wrap의 AAD. kind와 params를 묶어 KDF 파라미터를 낮추는 변조를 막는다.
    fn aad(&self) -> Result<Vec<u8>> {
        Ok([
            self.kind.as_bytes(),
            b"\0",
            &serde_json::to_vec(&self.params)?,
        ]
        .concat())
    }

    fn wrap(kind: &str, params: serde_json::Value, kek: &[u8; 32], dek: &Dek) -> Result<Slot> {
        let mut slot = Slot {
            kind: kind.into(),
            params,
            nonce: [0; NONCE_LEN],
            wrapped: vec![],
        };
        (slot.nonce, slot.wrapped) = aead_seal(kek, dek.as_ref(), &slot.aad()?)?;
        Ok(slot)
    }

    fn unwrap(&self, kek: &[u8; 32]) -> Result<Dek> {
        let plain = aead_open(kek, &self.nonce, &self.wrapped, &self.aad()?)?;
        let dek: [u8; 32] = plain.as_slice().try_into().map_err(|_| "bad DEK length")?;
        Ok(Zeroizing::new(dek))
    }

    fn passphrase(
        passphrase: &[u8],
        [m_cost, t_cost, p_cost]: [u32; 3],
        dek: &Dek,
    ) -> Result<Slot> {
        let p = PassphraseParams {
            salt: random()?,
            m_cost,
            t_cost,
            p_cost,
        };
        let kek = passphrase_kek(passphrase, &p)?;
        Slot::wrap(PASSPHRASE, serde_json::to_value(p)?, &kek, dek)
    }
}

fn passphrase_kek(passphrase: &[u8], p: &PassphraseParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(32))?;
    let mut kek = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(
        passphrase,
        &p.salt,
        kek.as_mut(),
    )?;
    Ok(kek)
}

impl Header {
    /// 파일에서 헤더를 읽는다. 두 번째 값은 본문 AAD의 길이(MAGIC부터 헤더 끝까지)다.
    pub fn parse(file: &[u8]) -> Result<(Header, usize)> {
        if file.get(..4) != Some(MAGIC) {
            return Err("not a sagevault vault".into());
        }
        let len = u32::from_le_bytes(file.get(4..8).ok_or("truncated")?.try_into()?) as usize;
        let end = 8usize.checked_add(len).ok_or("truncated")?;
        let header: Header = serde_json::from_slice(file.get(8..end).ok_or("truncated")?)?;
        if header.version != VERSION {
            return Err(format!("unsupported vault version {}", header.version).into());
        }
        Ok((header, end))
    }

    /// 패스프레이즈 슬롯들로 DEK를 푼다.
    pub fn unlock_passphrase(&self, passphrase: &[u8]) -> Result<Dek> {
        for slot in self.slots.iter().filter(|s| s.kind == PASSPHRASE) {
            let p: PassphraseParams = serde_json::from_value(slot.params.clone())?;
            if let Ok(dek) = slot.unwrap(&*passphrase_kek(passphrase, &p)?) {
                return Ok(dek);
            }
        }
        Err("wrong passphrase".into())
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn has_slot(&self, kind: &str) -> bool {
        self.slots.iter().any(|s| s.kind == kind)
    }

    /// 새 슬롯을 추가한다. 헤더가 바뀌므로 호출한 쪽이 seal로 본문을 다시 써야 한다.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn add_slot(
        &mut self,
        kind: &str,
        params: serde_json::Value,
        kek: &[u8; 32],
        dek: &Dek,
    ) -> Result<()> {
        self.slots.push(Slot::wrap(kind, params, kek, dek)?);
        Ok(())
    }

    /// kind 슬롯을 모두 지우고 지운 개수를 돌려준다. 패스프레이즈 슬롯은 복구 경로라 지우지 않는다.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn remove_slots(&mut self, kind: &str) -> usize {
        assert_ne!(kind, PASSPHRASE, "the passphrase slot is the recovery path");
        let before = self.slots.len();
        self.slots.retain(|s| s.kind != kind);
        before - self.slots.len()
    }

    /// kind 슬롯마다 kek_of(params)로 KEK를 얻어 DEK를 푼다. 처음 성공한 것을 돌려준다.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn unlock_slot(
        &self,
        kind: &str,
        kek_of: impl Fn(&serde_json::Value) -> Result<Zeroizing<[u8; 32]>>,
    ) -> Result<Dek> {
        let mut last: Result<Dek> = Err(format!("no {kind} slot").into());
        for slot in self.slots.iter().filter(|s| s.kind == kind) {
            last = kek_of(&slot.params).and_then(|kek| slot.unwrap(&kek));
            if last.is_ok() {
                break;
            }
        }
        last
    }
}

/// 키 합의(ECDH) 공유 비밀을 슬롯 KEK로 만든다. context(임시 공개키 등)로 슬롯마다 다른 키가 된다.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn derive_kek(shared: &[u8], context: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    use blake2::Blake2bMac;
    use blake2::digest::Mac;
    use blake2::digest::consts::U32;
    let mut m = Blake2bMac::<U32>::new_with_salt_and_personal(Some(shared), &[], b"sbx-slot-kek")
        .map_err(|_| "invalid shared secret length")?;
    m.update(context);
    Ok(Zeroizing::new(m.finalize().into_bytes().into()))
}

/// 새 DEK와 패스프레이즈 슬롯 하나로 볼트 파일을 만든다.
pub fn create(vault: &Vault, passphrase: &[u8], kdf: [u32; 3]) -> Result<(Vec<u8>, Dek)> {
    let dek = Zeroizing::new(random::<32>()?);
    let header = Header {
        version: VERSION,
        slots: vec![Slot::passphrase(passphrase, kdf, &dek)?],
    };
    Ok((seal(&header, vault, &dek)?, dek))
}

/// 기존 슬롯을 유지한 채 본문만 새 nonce로 다시 암호화한다.
pub fn seal(header: &Header, vault: &Vault, dek: &Dek) -> Result<Vec<u8>> {
    let header_json = serde_json::to_vec(header)?;
    let aad = [
        MAGIC,
        &(header_json.len() as u32).to_le_bytes()[..],
        &header_json,
    ]
    .concat();
    // ponytail: Vec 재할당 시 이전 버퍼에 평문 조각이 남을 수 있음. 문제되면 크기 예측 후 with_capacity로 한 번에 할당
    let plain = Zeroizing::new(serde_json::to_vec(vault)?);
    let (nonce, ct) = aead_seal(dek, &plain, &aad)?;
    Ok([&aad[..], &nonce, &ct].concat())
}

/// DEK로 본문을 복호화한다. 헤더(슬롯 포함)가 변조되면 AAD 불일치로 실패한다.
pub fn open(file: &[u8], dek: &Dek) -> Result<(Header, Vault)> {
    let (header, aad_len) = Header::parse(file)?;
    let (aad, rest) = file.split_at(aad_len);
    let nonce = rest.get(..NONCE_LEN).ok_or("truncated")?.try_into()?;
    let plain = aead_open(dek, nonce, &rest[NONCE_LEN..], aad)?;
    Ok((header, serde_json::from_slice(&plain)?))
}

/// 같은 디렉터리의 임시 파일(Unix는 0600)에 쓰고 rename해 원자적으로 교체한다.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 테스트는 가벼운 KDF 파라미터로 속도를 확보한다.
    const FAST: [u32; 3] = [64, 1, 1];

    fn fixture() -> (Vec<u8>, Dek, Vault) {
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
        let (file, dek) = create(&v, b"correct horse", FAST).unwrap();
        (file, dek, v)
    }

    #[test]
    fn roundtrip_via_passphrase() {
        let (file, dek, v) = fixture();
        let (header, _) = Header::parse(&file).unwrap();
        assert_eq!(*header.unlock_passphrase(b"correct horse").unwrap(), *dek);
        let (_, back) = open(&file, &dek).unwrap();
        assert_eq!(back.secrets["gh"].as_str(), "ghp_123");
        assert_eq!(back.profiles, v.profiles);
        assert!(
            !file.windows(7).any(|w| w == b"ghp_123"),
            "plaintext leaked"
        );
    }

    #[test]
    fn reseal_keeps_dek_and_uses_fresh_nonce() {
        let (file, dek, v) = fixture();
        let (header, _) = Header::parse(&file).unwrap();
        let again = seal(&header, &v, &dek).unwrap();
        assert_ne!(again, file);
        let (h2, _) = Header::parse(&again).unwrap();
        assert_eq!(*h2.unlock_passphrase(b"correct horse").unwrap(), *dek);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let (file, _, _) = fixture();
        let (header, _) = Header::parse(&file).unwrap();
        assert!(header.unlock_passphrase(b"wrong").is_err());
    }

    #[test]
    fn body_tampering_rejected() {
        let (file, dek, _) = fixture();
        for i in [0, 5, file.len() - 30, file.len() - 1] {
            let mut bad = file.clone();
            bad[i] ^= 1;
            assert!(open(&bad, &dek).is_err(), "byte {i} tamper accepted");
        }
        assert!(open(&file[..10], &dek).is_err());
    }

    #[test]
    fn weakened_kdf_params_rejected() {
        let (file, dek, v) = fixture();
        let (mut header, _) = Header::parse(&file).unwrap();
        header.slots[0].params["t_cost"] = 2.into();
        assert!(header.unlock_passphrase(b"correct horse").is_err());
        // 헤더를 바꾼 뒤 원래 본문을 붙이면 본문 AAD가 맞지 않는다.
        let forged = seal(&header, &v, &dek).unwrap();
        let (_, aad_len) = Header::parse(&file).unwrap();
        let (_, forged_aad_len) = Header::parse(&forged).unwrap();
        let spliced = [&forged[..forged_aad_len], &file[aad_len..]].concat();
        assert!(open(&spliced, &dek).is_err());
    }

    #[test]
    fn unknown_slot_preserved() {
        let (file, dek, v) = fixture();
        let (mut header, _) = Header::parse(&file).unwrap();
        let foreign = Slot::wrap(
            "secure_enclave",
            serde_json::json!({"key": [1, 2]}),
            &[7; 32],
            &dek,
        )
        .unwrap();
        header.slots.push(foreign.clone());
        let (h2, _) = open(&seal(&header, &v, &dek).unwrap(), &dek).unwrap();
        assert_eq!(h2.slots[1], foreign);
        assert_eq!(*h2.slots[1].unwrap(&[7; 32]).unwrap(), *dek);
        assert_eq!(*h2.unlock_passphrase(b"correct horse").unwrap(), *dek);
    }

    #[test]
    fn extra_slot_add_unlock_remove() {
        let (file, dek, v) = fixture();
        let (mut header, _) = Header::parse(&file).unwrap();
        // 하드웨어 대신 고정 공유 비밀로 슬롯 API만 검증한다.
        let (shared, epk) = ([9u8; 32], vec![4u8; 65]);
        let kek = derive_kek(&shared, &epk).unwrap();
        assert_ne!(
            *kek,
            *derive_kek(&shared, &[5u8; 65]).unwrap(),
            "context must matter"
        );
        let params = serde_json::json!({ "epk": epk });
        header
            .add_slot("secure_enclave", params, &kek, &dek)
            .unwrap();
        let file = seal(&header, &v, &dek).unwrap();

        let (h, _) = Header::parse(&file).unwrap();
        assert!(h.has_slot("secure_enclave"));
        let got = h
            .unlock_slot("secure_enclave", |p| {
                let epk: Vec<u8> = serde_json::from_value(p["epk"].clone())?;
                derive_kek(&shared, &epk)
            })
            .unwrap();
        assert_eq!(*got, *dek);
        // 공유 비밀이 다르면(다른 기기, 다른 키) 풀리지 않는다.
        assert!(
            h.unlock_slot("secure_enclave", |_| derive_kek(&[1u8; 32], &epk))
                .is_err()
        );
        assert!(
            h.unlock_slot("missing", |_| derive_kek(&shared, &epk))
                .is_err()
        );

        let mut h = h;
        assert_eq!(h.remove_slots("secure_enclave"), 1);
        assert!(!h.has_slot("secure_enclave") && h.has_slot(PASSPHRASE));
        assert_eq!(*h.unlock_passphrase(b"correct horse").unwrap(), *dek);
    }

    #[test]
    fn dates_and_expiry() {
        assert_eq!(parse_date("1970-01-01").unwrap(), 0);
        assert_eq!(parse_date("2000-03-01").unwrap(), 951_868_800);
        assert_eq!(parse_date("2024-02-29").unwrap(), 1_709_164_800);
        assert_eq!(parse_date("2026-09-28").unwrap(), 1_790_553_600);
        for bad in [
            "2025-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-9-28",
            "tomorrow",
            "2026-04-31",
        ] {
            assert!(parse_date(bad).is_err(), "{bad}");
        }
        let mut v = Vault::default();
        v.expires.insert("gh".into(), "2026-09-28".into());
        let names = ["gh".to_string(), "other".to_string()];
        assert!(v.check_expiry(&names, 1_790_553_599).is_ok());
        assert!(v.check_expiry(&names, 1_790_553_600).is_err());
        // 예전 형식(expires 없음)도 읽힌다.
        let old: Vault = serde_json::from_str(r#"{"secrets":{},"profiles":{}}"#).unwrap();
        assert!(old.expires.is_empty());
    }

    #[cfg(unix)]
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
