use std::ffi::CString;
use std::mem::{size_of, transmute};
use jni::JNIEnv;
use jni::objects::{JClass, JString, ReleaseMode};
use jni::sys::{jbyteArray, jint, jstring};
use nix::errno::errno;
use nix::libc::{c_void, setsockopt, SOL_SOCKET};
use nix::NixPath;
use nix::sys::socket::SockaddrLike;

#[repr(C)]
#[derive(Debug)]
struct TlsCryptoInfo {
    version: u16,
    cipher_type: u16,
}

#[repr(C)]
#[derive(Debug)]
struct Tls12CryptoInfoAesGcm128 {
    info: TlsCryptoInfo,
    iv: [i8; 8],
    key: [i8; 16],
    salt: [i8; 4],
    rec_seq: [i8; 8],
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
    let iv = env.get_byte_array_elements(iv, ReleaseMode::NoCopyBack).expect("Failed to get iv");
    let key = env.get_byte_array_elements(key, ReleaseMode::NoCopyBack).expect("Failed to get key");
    let salt = env.get_byte_array_elements(salt, ReleaseMode::NoCopyBack).expect("Failed to get salt");
    let rec_seq = env.get_byte_array_elements(rec_seq, ReleaseMode::NoCopyBack).expect("Failed to get rec_seq");

    let info = TlsCryptoInfo {
        version: 0x0303,
        cipher_type: 51,
    };
    let crypt_info = unsafe {
        Tls12CryptoInfoAesGcm128 {
            info,
            iv: transmute(*(iv.as_ptr() as *const [i8; 8])),
            key: transmute(*(key.as_ptr() as *const [i8; 16])),
            salt: transmute(*(salt.as_ptr() as *const [i8; 4])),
            rec_seq: transmute(*(rec_seq.as_ptr() as *const [i8; 8])),
        }
    };

    println!("crypt info: version: {:?}", &crypt_info);
    let ret = unsafe {
        setsockopt(fd, 282, 1, transmute((&crypt_info) as *const Tls12CryptoInfoAesGcm128), size_of::<Tls12CryptoInfoAesGcm128>() as u32)
    };
    if ret != 0 {
        env.throw(format!("Failed to setsockopt fot tls. returned: {}, errno: {}", ret, errno()));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
