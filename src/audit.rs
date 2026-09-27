// 감사 로그를 JSON Lines로 쓰고, DEK에서 유도한 키로 줄마다 MAC 체인을 거는 모듈
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use blake2::Blake2bMac;
use blake2::digest::Mac;
use blake2::digest::consts::U32;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::vault::{Dek, Result};

pub type AuditKey = Zeroizing<[u8; 32]>;

fn mac(persona: &[u8], key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut m = Blake2bMac::<U32>::new_with_salt_and_personal(Some(key), &[], persona)
        .map_err(|_| "invalid MAC key")?;
    m.update(data);
    Ok(m.finalize().into_bytes().into())
}

/// 감사 전용 키. 이 키로는 볼트를 열 수 없고, DEK가 같으면 항상 같은 값이다.
pub fn derive_key(dek: &Dek) -> Result<AuditKey> {
    Ok(Zeroizing::new(mac(b"sbx-audit-key", dek.as_ref(), &[])?))
}

/// `mac` 필드를 뺀 줄의 MAC. serde_json의 Map은 키 순서가 정렬돼 있어 직렬화가 결정적이다.
fn line_mac(key: &AuditKey, entry: &Value) -> Result<String> {
    let m = mac(b"sbx-audit-line", key.as_ref(), &serde_json::to_vec(entry)?)?;
    Ok(m.iter().map(|b| format!("{b:02x}")).collect())
}

fn read_lines(path: &Path) -> Result<Vec<String>> {
    match std::fs::File::open(path) {
        Ok(f) => Ok(BufReader::new(f).lines().collect::<std::io::Result<_>>()?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.into()),
    }
}

// 데몬(Unix 전용)만 쓴다. Windows에서도 모듈과 테스트는 컴파일되게 둔다.
#[cfg_attr(not(unix), allow(dead_code))]
pub struct AuditLog {
    path: PathBuf,
    key: Option<AuditKey>,
    seq: u64,
    prev: Option<String>,
}

#[cfg_attr(not(unix), allow(dead_code))]
impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        AuditLog {
            path,
            key: None,
            seq: 0,
            prev: None,
        }
    }

    /// 첫 unlock에서 한 번 호출된다. 파일의 마지막 체인 위치에서 이어 쓴다.
    pub fn set_key(&mut self, key: AuditKey) -> Result<()> {
        if self.key.is_some() {
            return Ok(());
        }
        for line in read_lines(&self.path)? {
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let (Some(seq), Some(mac)) = (v["seq"].as_u64(), v["mac"].as_str()) {
                self.seq = seq;
                self.prev = Some(mac.to_string());
            }
        }
        self.key = Some(key);
        Ok(())
    }

    /// 키가 있으면 seq·prev·mac을 붙여 체인에 넣고, 없으면(첫 unlock 전) 그대로 쓴다.
    pub fn append(&mut self, mut entry: Value) -> Result<()> {
        let mut next = None;
        if let Some(key) = &self.key {
            let seq = self.seq + 1;
            entry["seq"] = seq.into();
            entry["prev"] = self.prev.clone().into();
            let m = line_mac(key, &entry)?;
            entry["mac"] = m.clone().into();
            next = Some((seq, m));
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        writeln!(opts.open(&self.path)?, "{entry}")?;
        // 쓰기에 성공한 뒤에만 체인을 전진시킨다.
        if let Some((seq, m)) = next {
            self.seq = seq;
            self.prev = Some(m);
        }
        Ok(())
    }
}

pub struct Report {
    pub verified: u64,
    pub unauthenticated: u64,
    pub problems: Vec<String>,
}

/// 수정·위조(MAC 불일치), 중간 삭제(prev 불일치), 순번 건너뜀을 찾는다.
/// 끝부분을 잘라내거나 파일을 통째로 지우는 것은 잡지 못한다.
pub fn verify(path: &Path, key: &AuditKey) -> Result<Report> {
    let mut r = Report {
        verified: 0,
        unauthenticated: 0,
        problems: vec![],
    };
    let (mut seq, mut prev) = (0u64, None::<String>);
    for (i, line) in read_lines(path)?.iter().enumerate() {
        let n = i + 1;
        let Ok(mut v) = serde_json::from_str::<Value>(line) else {
            r.problems.push(format!("line {n}: not valid JSON"));
            continue;
        };
        let Some(Value::String(m)) = v.as_object_mut().and_then(|o| o.remove("mac")) else {
            r.unauthenticated += 1;
            continue;
        };
        if line_mac(key, &v)? != m {
            r.problems
                .push(format!("line {n}: MAC mismatch (edited or forged)"));
        }
        if v["seq"].as_u64() != Some(seq + 1) {
            r.problems
                .push(format!("line {n}: sequence gap after seq {seq}"));
        }
        if v["prev"].as_str() != prev.as_deref() {
            r.problems.push(format!(
                "line {n}: chain broken (a record before it was removed or altered)"
            ));
        }
        seq = v["seq"].as_u64().unwrap_or(seq + 1);
        prev = Some(m);
        r.verified += 1;
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("sbx-audit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn key(b: u8) -> AuditKey {
        derive_key(&Zeroizing::new([b; 32])).unwrap()
    }

    #[test]
    fn chain_detects_edit_delete_and_wrong_key() {
        let p = tmp("chain");
        let mut log = AuditLog::new(p.clone());
        log.append(json!({"op": "unlock", "result": "denied"}))
            .unwrap(); // 키 없음
        log.set_key(key(1)).unwrap();
        for i in 0..3 {
            log.append(json!({"op": "exec", "n": i})).unwrap();
        }
        // 데몬 재시작: 새 인스턴스가 파일 끝에서 체인을 이어간다.
        let mut log2 = AuditLog::new(p.clone());
        log2.set_key(key(1)).unwrap();
        log2.append(json!({"op": "lock"})).unwrap();

        let r = verify(&p, &key(1)).unwrap();
        assert_eq!((r.verified, r.unauthenticated), (4, 1));
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert!(
            !verify(&p, &key(2)).unwrap().problems.is_empty(),
            "wrong key accepted"
        );

        let lines: Vec<String> = read_lines(&p).unwrap();
        // 수정
        let edited = lines.join("\n").replace(r#""n":1"#, r#""n":9"#);
        std::fs::write(&p, edited).unwrap();
        assert!(verify(&p, &key(1)).unwrap().problems[0].contains("MAC mismatch"));
        // 중간 삭제
        let mut deleted = lines.clone();
        deleted.remove(2);
        std::fs::write(&p, deleted.join("\n")).unwrap();
        let probs = verify(&p, &key(1)).unwrap().problems;
        assert!(
            probs.iter().any(|s| s.contains("chain broken")),
            "{probs:?}"
        );

        std::fs::remove_file(p).unwrap();
    }
}
