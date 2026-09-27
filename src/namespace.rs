// 프로젝트별 네임스페이스(볼트·세션·감사 로그 분리)를 인자·환경변수·.secretbox 파일로 결정하는 모듈
use std::path::{Path, PathBuf};

use crate::vault::Result;

pub const DEFAULT: &str = "default";

/// 결정된 네임스페이스. source는 어디서 정해졌는지(--ns, SECRETBOX_NS, .secretbox 경로, default).
pub struct Ns {
    pub name: String,
    pub source: String,
    pub dir: PathBuf,
    /// .secretbox 파일로 이름 있는 네임스페이스가 정해졌을 때 그 파일이 있는 디렉터리(정규화).
    /// 이 경로는 그 네임스페이스에 신뢰 등록(`trust`)돼 있어야 exec가 허용된다.
    pub project: Option<PathBuf>,
}
const FILE: &str = ".secretbox";

/// 디렉터리 이름이 되므로 경로 탈출을 막고, Unix 소켓 경로 길이(macOS 104바이트) 안에 들게 짧게 제한한다.
pub fn validate(name: &str) -> Result<()> {
    let ok = (1..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(format!("invalid namespace {name:?} (use [a-z0-9][a-z0-9_-], max 32)").into())
    }
}

/// default는 기존 경로(root) 그대로, 나머지는 root/ns/<name>.
pub fn dir(root: &Path, name: &str) -> PathBuf {
    if name == DEFAULT {
        root.to_path_buf()
    } else {
        root.join("ns").join(name)
    }
}

/// `namespace = "acme"` 한 줄을 읽는다. 따옴표는 있어도 없어도 된다.
fn parse_file(content: &str) -> Result<String> {
    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=')
            && key.trim() == "namespace"
        {
            return Ok(value.trim().trim_matches('"').to_string());
        }
    }
    Err("no `namespace = \"...\"` line".into())
}

/// start부터 위로 올라가며 가장 가까운 .secretbox 파일을 찾는다. 디렉터리(~/.secretbox)는 무시한다.
fn find_file(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|d| d.join(FILE))
        .find(|p| p.is_file())
}

/// (이름, 출처, 프로젝트 디렉터리). 순서는 --ns > SECRETBOX_NS > .secretbox 파일 > default.
/// 프로젝트 디렉터리는 저장소 파일이 이름 있는 네임스페이스를 골랐을 때만 채운다.
pub fn resolve(
    flag: Option<&str>,
    env: Option<String>,
    cwd: &Path,
) -> Result<(String, String, Option<PathBuf>)> {
    let (name, source, project) = if let Some(n) = flag {
        (n.to_string(), "--ns".to_string(), None)
    } else if let Some(n) = env.filter(|n| !n.is_empty()) {
        (n, "SECRETBOX_NS".to_string(), None)
    } else if let Some(file) = find_file(cwd) {
        let name = parse_file(&std::fs::read_to_string(&file)?)
            .map_err(|e| format!("{}: {e}", file.display()))?;
        let dir = file.parent().ok_or("no parent")?.canonicalize()?;
        (name, file.display().to_string(), Some(dir))
    } else {
        (DEFAULT.to_string(), "default".to_string(), None)
    };
    validate(&name).map_err(|e| format!("{e} (from {source})"))?;
    let project = project.filter(|_| name != DEFAULT);
    Ok((name, source, project))
}

/// 볼트가 있는 네임스페이스 목록.
pub fn list(root: &Path) -> Vec<String> {
    let mut names = vec![];
    if root.join("vault").is_file() {
        names.push(DEFAULT.to_string());
    }
    if let Ok(entries) = std::fs::read_dir(root.join("ns")) {
        let mut rest: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().join("vault").is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        rest.sort();
        names.extend(rest);
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["default", "acme", "a", "my-proj_2", "0x"] {
            assert!(validate(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "..",
            "../x",
            "a/b",
            "Acme",
            "-a",
            "_a",
            "a b",
            &"x".repeat(33),
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn file_format() {
        assert_eq!(parse_file("namespace = \"acme\"\n").unwrap(), "acme");
        assert_eq!(parse_file("# c\nnamespace=acme").unwrap(), "acme");
        assert!(parse_file("name = acme").is_err());
    }

    #[test]
    fn precedence() {
        let root = std::env::temp_dir().join(format!("sbx-ns-{}", std::process::id()));
        let deep = root.join("proj/src/deep");
        std::fs::create_dir_all(&deep).unwrap();
        // 상위 디렉터리에 같은 이름의 "디렉터리"가 있어도 파일만 인정한다.
        std::fs::create_dir_all(root.join(FILE)).unwrap();
        let (n, _, p) = resolve(None, None, &deep).unwrap();
        assert_eq!((n.as_str(), p), (DEFAULT, None));

        std::fs::write(root.join("proj").join(FILE), "namespace = \"acme\"\n").unwrap();
        let (n, src, p) = resolve(None, None, &deep).unwrap();
        assert_eq!((n.as_str(), src.ends_with(FILE)), ("acme", true));
        assert_eq!(p, Some(root.join("proj").canonicalize().unwrap()));
        // 명시 인자로 고르면 프로젝트 신뢰 검사 대상이 아니다.
        assert_eq!(resolve(Some("acme"), None, &deep).unwrap().2, None);
        assert_eq!(resolve(None, Some("beta".into()), &deep).unwrap().0, "beta");
        assert_eq!(
            resolve(Some("gamma"), Some("beta".into()), &deep)
                .unwrap()
                .0,
            "gamma"
        );

        // 저장소 파일이 경로 탈출을 시도하면 거부한다.
        std::fs::write(root.join("proj").join(FILE), "namespace = \"../../etc\"\n").unwrap();
        assert!(resolve(None, None, &deep).is_err());

        assert_eq!(dir(&root, DEFAULT), root);
        assert_eq!(dir(&root, "acme"), root.join("ns/acme"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
