// macOS 전용 시스템 기능(화면 잠금 조회, Secure Enclave 키)을 프레임워크 FFI로 감싼 모듈
use std::ffi::{CStr, CString, c_char, c_void};

use zeroize::Zeroizing;

use crate::vault::Result;

type CFTypeRef = *const c_void;
type CFErrorRef = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanFalse: CFTypeRef;
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
    fn CFStringCreateWithCString(alloc: CFTypeRef, s: *const c_char, encoding: u32) -> CFTypeRef;
    fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, len: isize, encoding: u32) -> u8;
    fn CFDictionaryCreate(
        alloc: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: isize,
        key_cb: *const c_void,
        value_cb: *const c_void,
    ) -> CFTypeRef;
    fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFDataCreate(alloc: CFTypeRef, bytes: *const u8, len: isize) -> CFTypeRef;
    fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
    fn CFDataGetLength(data: CFTypeRef) -> isize;
    fn CFNumberCreate(alloc: CFTypeRef, kind: isize, value: *const c_void) -> CFTypeRef;
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFBooleanGetTypeID() -> usize;
    fn CFDataGetTypeID() -> usize;
    fn CFBooleanGetValue(b: CFTypeRef) -> u8;
    fn CFErrorGetCode(err: CFErrorRef) -> isize;
    fn CFCopyDescription(cf: CFTypeRef) -> CFTypeRef;
    fn CFRelease(cf: CFTypeRef);
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGSessionCopyCurrentDictionary() -> CFTypeRef;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrKeyType: CFTypeRef;
    static kSecAttrKeyTypeECSECPrimeRandom: CFTypeRef;
    static kSecAttrKeySizeInBits: CFTypeRef;
    static kSecAttrKeyClass: CFTypeRef;
    static kSecAttrKeyClassPrivate: CFTypeRef;
    static kSecAttrKeyClassPublic: CFTypeRef;
    static kSecAttrTokenID: CFTypeRef;
    static kSecAttrTokenIDSecureEnclave: CFTypeRef;
    static kSecAttrIsPermanent: CFTypeRef;
    static kSecAttrAccessControl: CFTypeRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFTypeRef;
    static kSecPrivateKeyAttrs: CFTypeRef;
    static kSecUseOperationPrompt: CFTypeRef;
    static kSecKeyAlgorithmECDHKeyExchangeStandard: CFTypeRef;
    fn SecAccessControlCreateWithFlags(
        alloc: CFTypeRef,
        protection: CFTypeRef,
        flags: u64,
        err: *mut CFErrorRef,
    ) -> CFTypeRef;
    fn SecKeyCreateRandomKey(params: CFTypeRef, err: *mut CFErrorRef) -> CFTypeRef;
    fn SecKeyCreateWithData(data: CFTypeRef, attrs: CFTypeRef, err: *mut CFErrorRef) -> CFTypeRef;
    fn SecKeyCopyAttributes(key: CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyPublicKey(key: CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyExternalRepresentation(key: CFTypeRef, err: *mut CFErrorRef) -> CFTypeRef;
    fn SecKeyCopyKeyExchangeResult(
        key: CFTypeRef,
        algorithm: CFTypeRef,
        public_key: CFTypeRef,
        params: CFTypeRef,
        err: *mut CFErrorRef,
    ) -> CFTypeRef;
}

const UTF8: u32 = 0x0800_0100;
const CF_NUMBER_SINT32: isize = 3;
const ACCESS_USER_PRESENCE: u64 = 1 << 0; // Touch ID → Watch → 로그인 암호 중 시스템이 고른다
const ACCESS_PRIVATE_KEY_USAGE: u64 = 1 << 30;

/// Copy/Create로 얻은 CF 객체. drop될 때 CFRelease한다.
struct Cf(CFTypeRef);

impl Drop for Cf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) }
        }
    }
}

fn cfstr(s: &CStr) -> Cf {
    Cf(unsafe { CFStringCreateWithCString(std::ptr::null(), s.as_ptr(), UTF8) })
}

fn cfdata(bytes: &[u8]) -> Cf {
    Cf(unsafe { CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as isize) })
}

fn dict(pairs: &[(CFTypeRef, CFTypeRef)]) -> Cf {
    let (keys, values): (Vec<_>, Vec<_>) = pairs.iter().copied().unzip();
    Cf(unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as isize,
            (&raw const kCFTypeDictionaryKeyCallBacks).cast(),
            (&raw const kCFTypeDictionaryValueCallBacks).cast(),
        )
    })
}

// ponytail: CFData 내부 버퍼(공유 비밀 사본)는 CFRelease로 해제될 뿐 0으로 지워지지 않는다
fn data_bytes(data: CFTypeRef) -> Option<Vec<u8>> {
    unsafe {
        if data.is_null() || CFGetTypeID(data) != CFDataGetTypeID() {
            return None;
        }
        let len = CFDataGetLength(data) as usize;
        Some(std::slice::from_raw_parts(CFDataGetBytePtr(data), len).to_vec())
    }
}

/// CFError를 Rust 오류로 바꾸고 해제한다. 사용자가 취소한 경우도 여기로 온다.
fn cf_error(err: CFErrorRef, what: &str) -> Box<dyn std::error::Error> {
    if err.is_null() {
        return format!("{what} failed").into();
    }
    let code = unsafe { CFErrorGetCode(err) };
    // LAError.userCancel(-2), errSecUserCanceled(-128): 사용자가 고른 정상 경로라 짧게 알린다.
    if code == -2 || code == -128 {
        drop(Cf(err));
        return format!("{what} cancelled by user").into();
    }
    let desc = Cf(unsafe { CFCopyDescription(err) });
    let mut buf = [0 as c_char; 512];
    let text = if unsafe { CFStringGetCString(desc.0, buf.as_mut_ptr(), 512, UTF8) } != 0 {
        unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    drop(Cf(err));
    format!("{what} failed (code {code}): {text}").into()
}

/// SecKey* 함수를 부르고, NULL이면 CFError를 돌려준다.
fn check(what: &str, f: impl FnOnce(*mut CFErrorRef) -> CFTypeRef) -> Result<Cf> {
    let mut err: CFErrorRef = std::ptr::null();
    let v = f(&mut err);
    if v.is_null() {
        Err(cf_error(err, what))
    } else {
        Ok(Cf(v))
    }
}

/// 로그인 세션의 화면이 잠겨 있는가. GUI 세션 밖(SSH 등)이라 알 수 없으면 None.
pub fn screen_locked() -> Option<bool> {
    // SAFETY: Copy/Create로 얻은 객체만 해제하고, Get으로 얻은 값은 dict가 살아 있는 동안만 쓴다.
    unsafe {
        let dict = Cf(CGSessionCopyCurrentDictionary());
        if dict.0.is_null() {
            return None;
        }
        let key = cfstr(c"CGSSessionScreenIsLocked");
        let value = CFDictionaryGetValue(dict.0, key.0);
        // 잠기지 않았을 때는 키 자체가 없다.
        Some(
            !value.is_null()
                && CFGetTypeID(value) == CFBooleanGetTypeID()
                && CFBooleanGetValue(value) != 0,
        )
    }
}

/// Secure Enclave 키. blob은 이 Mac의 SE만 풀 수 있는 암호화된 키(`toid`), public은 X9.63 공개키.
pub struct SeKey {
    pub blob: Vec<u8>,
    pub public: Vec<u8>,
}

fn public_key(x963: &[u8]) -> Result<Cf> {
    let attrs = unsafe {
        dict(&[
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
            (kSecAttrKeyClass, kSecAttrKeyClassPublic),
        ])
    };
    let data = cfdata(x963);
    check("load public key", |e| unsafe {
        SecKeyCreateWithData(data.0, attrs.0, e)
    })
}

fn export_public(private: &Cf) -> Result<Vec<u8>> {
    let public = Cf(unsafe { SecKeyCopyPublicKey(private.0) });
    let data = check("export public key", |e| unsafe {
        SecKeyCopyExternalRepresentation(public.0, e)
    })?;
    data_bytes(data.0).ok_or_else(|| "public key is not data".into())
}

fn ecdh(private: &Cf, peer: &Cf) -> Result<Zeroizing<Vec<u8>>> {
    let params = dict(&[]);
    let shared = check("key agreement", |e| unsafe {
        SecKeyCopyKeyExchangeResult(
            private.0,
            kSecKeyAlgorithmECDHKeyExchangeStandard,
            peer.0,
            params.0,
            e,
        )
    })?;
    Ok(Zeroizing::new(
        data_bytes(shared.0).ok_or("shared secret is not data")?,
    ))
}

/// 사용자 확인(userPresence)이 걸린 SE 키를 만든다. 키체인에 넣지 않으므로 entitlement가 필요 없다.
/// 만들 때는 대화상자가 뜨지 않는다.
pub fn se_create() -> Result<SeKey> {
    unsafe {
        let access = check("access control", |e| {
            SecAccessControlCreateWithFlags(
                std::ptr::null(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                ACCESS_PRIVATE_KEY_USAGE | ACCESS_USER_PRESENCE,
                e,
            )
        })?;
        let bits = 256i32;
        let bits = Cf(CFNumberCreate(
            std::ptr::null(),
            CF_NUMBER_SINT32,
            (&raw const bits).cast(),
        ));
        let private_attrs = dict(&[
            (kSecAttrIsPermanent, kCFBooleanFalse),
            (kSecAttrAccessControl, access.0),
        ]);
        let params = dict(&[
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
            (kSecAttrKeySizeInBits, bits.0),
            (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave),
            (kSecPrivateKeyAttrs, private_attrs.0),
        ]);
        let key = check("create Secure Enclave key", |e| {
            SecKeyCreateRandomKey(params.0, e)
        })?;
        let attrs = Cf(SecKeyCopyAttributes(key.0));
        let toid = cfstr(c"toid");
        let blob = data_bytes(CFDictionaryGetValue(attrs.0, toid.0))
            .ok_or("Secure Enclave key has no toid blob")?;
        Ok(SeKey {
            blob,
            public: export_public(&key)?,
        })
    }
}

/// 소프트웨어 임시 키로 SE 공개키와 ECDH한다. (임시 공개키, 공유 비밀). 대화상자 없음.
pub fn ephemeral_ecdh(se_public: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let bits = 256i32;
    let bits =
        Cf(unsafe { CFNumberCreate(std::ptr::null(), CF_NUMBER_SINT32, (&raw const bits).cast()) });
    let params = unsafe {
        dict(&[
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
            (kSecAttrKeySizeInBits, bits.0),
        ])
    };
    let eph = check("create ephemeral key", |e| unsafe {
        SecKeyCreateRandomKey(params.0, e)
    })?;
    let shared = ecdh(&eph, &public_key(se_public)?)?;
    Ok((export_public(&eph)?, shared))
}

/// SE 블롭으로 키를 되살려 peer 공개키와 ECDH한다. 이때 시스템 대화상자(Touch ID/로그인 암호)가 뜬다.
pub fn se_ecdh(blob: &[u8], peer_public: &[u8], reason: &str) -> Result<Zeroizing<Vec<u8>>> {
    let prompt = CString::new(reason.replace('\0', " "))?;
    let prompt = cfstr(&prompt);
    let (toid, blob) = (cfstr(c"toid"), cfdata(blob));
    let attrs = unsafe {
        dict(&[
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
            (kSecAttrKeyClass, kSecAttrKeyClassPrivate),
            (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave),
            (kSecUseOperationPrompt, prompt.0),
            (toid.0, blob.0),
        ])
    };
    // 블롭을 키 데이터로 넘기면 SE가 새 키를 만든다. 토큰 객체 ID(toid) 속성으로 넘겨야 기존 키를 가리킨다.
    let data = cfdata(&[]);
    let key = check("load Secure Enclave key", |e| unsafe {
        SecKeyCreateWithData(data.0, attrs.0, e)
    })?;
    ecdh(&key, &public_key(peer_public)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn screen_lock_query_runs() {
        // 값은 실행 환경(GUI 세션 여부)에 따라 다르므로, 호출이 안전하게 끝나는지만 본다.
        let _ = super::screen_locked();
    }

    /// 대화상자가 뜨므로 수동으로만 돌린다: cargo test se_roundtrip -- --ignored
    #[test]
    #[ignore]
    fn se_roundtrip() {
        let key = super::se_create().unwrap();
        let (epk, shared) = super::ephemeral_ecdh(&key.public).unwrap();
        let again =
            super::se_ecdh(&key.blob, &epk, "sagebox test: Secure Enclave round trip").unwrap();
        assert_eq!(*shared, *again);
    }

    /// 대화상자 없이 되는 부분: SE 키 생성과 소프트웨어 쪽 ECDH
    #[test]
    fn se_create_and_ephemeral_side() {
        let Ok(key) = super::se_create() else {
            return; // Secure Enclave가 없는 Mac(가상 머신 등)
        };
        assert_eq!(key.public.len(), 65);
        assert!(key.blob.len() > 100);
        let (epk, shared) = super::ephemeral_ecdh(&key.public).unwrap();
        assert_eq!((epk.len(), shared.len()), (65, 32));
    }
}
