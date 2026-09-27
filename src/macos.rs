// macOS 전용 시스템 조회(화면 잠금 상태 등)를 프레임워크 FFI로 감싼 모듈
use std::ffi::{c_char, c_void};

type CFTypeRef = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(alloc: CFTypeRef, s: *const c_char, encoding: u32) -> CFTypeRef;
    fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFBooleanGetTypeID() -> usize;
    fn CFBooleanGetValue(b: CFTypeRef) -> u8;
    fn CFRelease(cf: CFTypeRef);
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGSessionCopyCurrentDictionary() -> CFTypeRef;
}

const UTF8: u32 = 0x0800_0100;

/// 로그인 세션의 화면이 잠겨 있는가. GUI 세션 밖(SSH 등)이라 알 수 없으면 None.
pub fn screen_locked() -> Option<bool> {
    // SAFETY: Copy/Create로 얻은 객체만 CFRelease하고, Get으로 얻은 값은 dict가 살아 있는 동안만 쓴다.
    unsafe {
        let dict = CGSessionCopyCurrentDictionary();
        if dict.is_null() {
            return None;
        }
        let key =
            CFStringCreateWithCString(std::ptr::null(), c"CGSSessionScreenIsLocked".as_ptr(), UTF8);
        let value = CFDictionaryGetValue(dict, key);
        // 잠기지 않았을 때는 키 자체가 없다.
        let locked = !value.is_null()
            && CFGetTypeID(value) == CFBooleanGetTypeID()
            && CFBooleanGetValue(value) != 0;
        CFRelease(key);
        CFRelease(dict);
        Some(locked)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn screen_lock_query_runs() {
        // 값은 실행 환경(GUI 세션 여부)에 따라 다르므로, 호출이 안전하게 끝나는지만 본다.
        let _ = super::screen_locked();
    }
}
