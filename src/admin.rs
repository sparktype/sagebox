// 데몬을 거치지 않고 패스프레이즈로 볼트 파일을 직접 편집하는 관리 명령
use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal};
use std::path::Path;

use zeroize::Zeroizing;

use crate::vault::{self, Dek, Header, Profile, Result, Vault};

/// 터미널이면 에코 없이 묻고, 파이프면 stdin에서 한 줄 읽는다.
fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
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
    if *read_secret("repeat passphrase: ")? != *pass {
        return Err("passphrases do not match".into());
    }
    let (file, _) = vault::create(&Vault::default(), pass.as_bytes(), vault::DEFAULT_KDF)?;
    vault::write_atomic(path, &file)
}

pub fn set(path: &Path, name: &str) -> Result<()> {
    edit(path, |v| {
        let value = read_secret(&format!("value for {name}: "))?;
        v.secrets.insert(name.into(), value);
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
        Ok(())
    })
}

/// 이름과 매핑만 출력한다. 비밀 값은 출력하지 않는다.
pub fn list(path: &Path) -> Result<()> {
    let (_, v, _) = unlock(path)?;
    println!("secrets:");
    for name in v.secrets.keys() {
        println!("  {name}");
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
