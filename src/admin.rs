// 데몬을 거치지 않고 패스프레이즈로 볼트 파일을 직접 편집하는 관리 명령
use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal};
use std::path::Path;

use zeroize::Zeroizing;

use crate::audit;
use crate::vault::{self, Dek, Header, Profile, Result, Vault};

/// 볼트 파일은 같은 UID면 복사해 오프라인 대입 공격을 할 수 있으므로 길이 하한을 둔다.
const MIN_PASSPHRASE: usize = 8;
/// 프로필이 덮어쓰면 실행 환경이 깨지는 변수. `LD_*`·`DYLD_*` 로더 변수는 접두어로 따로 막는다.
const RESERVED_ENV: &[&str] = &[
    "PATH", "HOME", "USER", "SHELL", "PWD", "OLDPWD", "TERM", "LANG", "IFS", "LC_ALL", "LC_CTYPE",
];

/// POSIX 이름(`[A-Za-z_][A-Za-z0-9_]*`)이고 예약 변수가 아니어야 한다.
fn check_env_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let valid = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(format!("invalid environment variable name: {name:?}").into());
    }
    if RESERVED_ENV.contains(&name) || name.starts_with("LD_") || name.starts_with("DYLD_") {
        return Err(format!("refusing to override reserved variable {name}").into());
    }
    Ok(())
}

/// 터미널이면 에코 없이 묻고, 파이프면 stdin에서 한 줄 읽는다.
pub(crate) fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
    let mut s = if std::io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password(prompt)?)
    } else {
        let mut s = Zeroizing::new(String::new());
        std::io::stdin().lock().read_line(&mut s)?;
        s
    };
    let len = s.trim_end_matches(['\r', '\n']).len();
    s.truncate(len);
    if s.is_empty() {
        return Err(format!("empty input for {prompt:?}").into());
    }
    Ok(s)
}

fn unlock(path: &Path) -> Result<(Header, Vault, Dek)> {
    let file = std::fs::read(path)
        .map_err(|e| format!("{}: {e} (run `secretbox init` first)", path.display()))?;
    let (header, _) = Header::parse(&file)?;
    let dek = header.unlock_passphrase(read_secret("passphrase: ")?.as_bytes())?;
    let (header, vault) = vault::open(&file, &dek)?;
    Ok((header, vault, dek))
}

/// 볼트를 열어 f로 고친 뒤 같은 슬롯으로 다시 저장한다.
// ponytail: 동시에 두 관리 명령이 돌면 나중에 쓴 쪽이 이긴다. 필요해지면 파일 잠금 추가
fn edit(path: &Path, f: impl FnOnce(&mut Vault) -> Result<()>) -> Result<()> {
    let (header, mut vault, dek) = unlock(path)?;
    f(&mut vault)?;
    vault::write_atomic(path, &vault::seal(&header, &vault, &dek)?)
}

pub fn init(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(format!("{} already exists", path.display()).into());
    }
    let pass = read_secret("new passphrase: ")?;
    if pass.chars().count() < MIN_PASSPHRASE {
        return Err(format!("passphrase must be at least {MIN_PASSPHRASE} characters").into());
    }
    if *read_secret("repeat passphrase: ")? != *pass {
        return Err("passphrases do not match".into());
    }
    let (file, _) = vault::create(&Vault::default(), pass.as_bytes(), vault::DEFAULT_KDF)?;
    vault::write_atomic(path, &file)
}

/// expires가 없으면 기존 만료일을 지운다(새 값은 대개 새 토큰이기 때문이다).
pub fn set(path: &Path, name: &str, expires: Option<&str>) -> Result<()> {
    if let Some(date) = expires
        && vault::parse_date(date)? <= vault::unix_now()
    {
        return Err(format!("expiry date {date} is not in the future").into());
    }
    edit(path, |v| {
        let value = read_secret(&format!("value for {name}: "))?;
        // 환경변수 값에는 NUL이 들어갈 수 없어 exec 때 실패하므로 저장 시점에 막는다.
        if value.contains('\0') {
            return Err("secret value must not contain NUL bytes".into());
        }
        v.secrets.insert(name.into(), value);
        match expires {
            Some(date) => v.expires.insert(name.into(), date.into()),
            None => v.expires.remove(name),
        };
        Ok(())
    })
}

pub fn rm(path: &Path, name: &str) -> Result<()> {
    edit(path, |v| {
        let users: Vec<&str> = v
            .profiles
            .iter()
            .filter(|(_, p)| p.env.values().any(|s| s == name))
            .map(|(n, _)| n.as_str())
            .collect();
        if !users.is_empty() {
            return Err(format!("{name} is used by profiles: {}", users.join(", ")).into());
        }
        v.secrets
            .remove(name)
            .ok_or(format!("no secret named {name}"))?;
        v.expires.remove(name);
        Ok(())
    })
}

/// 이름과 매핑만 출력한다. 비밀 값은 출력하지 않는다.
pub fn list(path: &Path) -> Result<()> {
    let (_, v, _) = unlock(path)?;
    println!("secrets:");
    let now = vault::unix_now();
    for name in v.secrets.keys() {
        match v.expires.get(name) {
            Some(d) if v.check_expiry([name], now).is_err() => println!("  {name}  (EXPIRED {d})"),
            Some(d) => println!("  {name}  (expires {d})"),
            None => println!("  {name}"),
        }
    }
    if !v.trusted.is_empty() {
        println!("trusted projects:");
        for dir in &v.trusted {
            println!("  {dir}");
        }
    }
    println!("profiles:");
    for (name, p) in &v.profiles {
        let env: Vec<String> = p.env.iter().map(|(k, s)| format!("{k}={s}")).collect();
        println!("  {name}: [{}] {}", env.join(" "), p.command.join(" "));
    }
    Ok(())
}

pub fn profile_add(
    path: &Path,
    name: &str,
    env: BTreeMap<String, String>,
    command: Vec<String>,
) -> Result<()> {
    // PATH 조작으로 다른 실행 파일이 끼어들지 않도록 절대경로만 받는다.
    match command.first() {
        Some(bin) if Path::new(bin).is_absolute() => {}
        _ => return Err("command must start with an absolute path".into()),
    }
    for var in env.keys() {
        check_env_name(var)?;
    }
    edit(path, |v| {
        if let Some(missing) = env.values().find(|s| !v.secrets.contains_key(*s)) {
            return Err(format!("no secret named {missing}").into());
        }
        v.profiles.insert(name.into(), Profile { command, env });
        Ok(())
    })
}

pub fn profile_rm(path: &Path, name: &str) -> Result<()> {
    edit(path, |v| {
        v.profiles
            .remove(name)
            .ok_or(format!("no profile named {name}"))?;
        Ok(())
    })
}

/// 이 네임스페이스의 패스프레이즈로 프로젝트 디렉터리를 신뢰 등록한다.
pub fn trust(path: &Path, project: &Path) -> Result<()> {
    edit(path, |v| {
        v.trusted.insert(project.display().to_string());
        Ok(())
    })
}

pub fn untrust(path: &Path, project: &str) -> Result<()> {
    edit(path, |v| {
        if !v.trusted.remove(project) {
            return Err(format!("{project} is not trusted").into());
        }
        Ok(())
    })
}

/// 패스프레이즈로 감사 키를 얻어 audit.log의 MAC 체인을 검증한다.
pub fn audit_verify(vault_path: &Path, audit_path: &Path) -> Result<()> {
    let (_, _, dek) = unlock(vault_path)?;
    let r = audit::verify(audit_path, &audit::derive_key(&dek)?)?;
    println!(
        "{} verified, {} unauthenticated (written before the daemon's first unlock)",
        r.verified, r.unauthenticated
    );
    if r.problems.is_empty() {
        return Ok(());
    }
    for p in &r.problems {
        println!("  {p}");
    }
    Err(format!(
        "audit log failed verification ({} problems)",
        r.problems.len()
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::check_env_name;

    #[test]
    fn env_names() {
        for ok in ["GITHUB_TOKEN", "_X", "a1"] {
            assert!(check_env_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "1X",
            "A-B",
            "A B",
            "A=B",
            "PATH",
            "HOME",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
        ] {
            assert!(check_env_name(bad).is_err(), "{bad}");
        }
    }
}
