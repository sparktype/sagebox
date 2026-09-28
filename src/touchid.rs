// Secure Enclave 키로 볼트를 여는 secure_enclave 슬롯(Touch ID·Apple Watch·로그인 암호 확인)을 관리하는 모듈
use std::path::Path;

use serde_json::json;

use crate::admin;
use crate::macos;
use crate::vault::{self, Dek, Header, Result};

pub const KIND: &str = "secure_enclave";

/// 패스프레이즈로 볼트를 열고 SE 슬롯을 추가한다. 키를 만들 때는 대화상자가 뜨지 않는다.
/// KEK는 소프트웨어 임시 키와 SE 공개키의 ECDH로 만들고, 풀 때는 SE 개인키로 같은 값을 얻는다.
pub fn enable(vault_path: &Path) -> Result<()> {
    admin::edit_header(vault_path, |h, dek| {
        if h.has_slot(KIND) {
            return Err("Touch ID is already enabled for this namespace".into());
        }
        add_slot(h, dek)
    })?;
    println!(
        "Touch ID enabled. `sagebox unlock` and locked `sagebox exec` will ask Touch ID (or your Mac login password when the lid is closed)."
    );
    Ok(())
}

/// 새 SE 키를 만들고 그 키로 DEK를 감싼 슬롯을 헤더에 추가한다(대화상자 없음).
/// 호출한 쪽이 seal로 볼트를 다시 써야 한다.
pub fn add_slot(h: &mut Header, dek: &Dek) -> Result<()> {
    let se = macos::se_create()?;
    let (epk, shared) = macos::ephemeral_ecdh(&se.public)?;
    let kek = vault::derive_kek(&shared, &epk)?;
    h.add_slot(KIND, json!({ "blob": se.blob, "epk": epk }), &kek, dek)
}

pub fn disable(vault_path: &Path) -> Result<()> {
    admin::edit_header(vault_path, |h, _| match h.remove_slots(KIND) {
        0 => Err("Touch ID is not enabled for this namespace".into()),
        _ => Ok(()),
    })?;
    println!("Touch ID disabled; the passphrase still unlocks this namespace.");
    Ok(())
}

pub fn status(vault_path: &Path) -> Result<()> {
    let (h, _) = Header::parse(&std::fs::read(vault_path)?)?;
    println!(
        "Touch ID: {}",
        if h.has_slot(KIND) {
            "enabled"
        } else {
            "disabled"
        }
    );
    Ok(())
}

/// SE 슬롯으로 DEK를 푼다. 슬롯이 없으면 Ok(None). 시스템 확인 대화상자가 뜬다.
pub fn unlock(vault_path: &Path, reason: &str) -> Result<Option<Dek>> {
    let file = std::fs::read(vault_path)?;
    let (h, _) = Header::parse(&file)?;
    if !h.has_slot(KIND) {
        return Ok(None);
    }
    let dek = h.unlock_slot(KIND, |p| {
        let blob: Vec<u8> = serde_json::from_value(p["blob"].clone())?;
        let epk: Vec<u8> = serde_json::from_value(p["epk"].clone())?;
        let shared = macos::se_ecdh(&blob, &epk, reason)?;
        vault::derive_kek(&shared, &epk)
    })?;
    vault::open(&file, &dek)?;
    Ok(Some(dek))
}
