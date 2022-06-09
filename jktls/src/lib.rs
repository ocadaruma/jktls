use std::ffi::CString;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jint, jstring};
use nix::errno::errno;
use nix::libc::{c_void, setsockopt, SOL_SOCKET};
use nix::NixPath;

#[repr(C)]
struct TlsCryptoInfo {
    version: u16,
    cipher_type: u16,
}

#[repr(C)]
struct Tls12CryptoInfoAesGcm128 {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 16],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

#[no_mangle]
pub extern "system" fn Java_sun_nio_ch_KTlsSocketChannelImpl_setTcpUlp(
    env: JNIEnv,
    class: JClass,
    fd: jint,
    name: JString) {
    let s: String = env.get_string(name).expect("failed to get JString").into();
    let s = CString::new(s).expect("failed to create CString");
    let ret = unsafe {
        setsockopt(fd, 6, 31, s.as_ptr() as *const c_void, s.len() as u32)
    };
    if ret != 0 {
        env.throw(format!("Failed to setsockopt. returned: {}, errno: {}", ret, errno()));
    }
}

#[no_mangle]
pub extern "system" fn Java_sun_nio_ch_KTlsSocketChannelImpl_setTlsTxTls12AesGcm128(
    env: JNIEnv,
    class: JClass,
    fd: jint,
    iv: jbyteArray,
    key: jbyteArray,
    salt: jbyteArray,
    rec_seq: jbyteArray) {
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
