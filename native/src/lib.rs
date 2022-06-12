use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;
use nix::errno::Errno;
use nix::libc::{c_int, c_void, setsockopt};
use std::mem::size_of;

const SOCKET_EXCEPTION_CLASS: &str = "java/net/SocketException";
const UNSUPPORTED_OPERATION_EXCEPTION_CLASS: &str = "java/lang/UnsupportedOperationException";
const ILLEGAL_ARGUMENT_EXCEPTION_CLASS: &str = "java/lang/IllegalArgumentException";

const SOL_TCP: c_int = 6;
const SOL_TLS: c_int = 282;
const TCP_ULP: c_int = 31;
const TLS_TX: c_int = 1;

#[derive(Debug)]
enum KTlsError {
    Socket { msg: String },
    UnsupportedOperation { msg: String },
    IllegalArgument { msg: String },
}

#[repr(u16)]
#[derive(Copy, Clone, Debug)]
enum TlsVersion {
    Tls12 = 0x0303,
}

#[repr(u16)]
#[derive(Copy, Clone, Debug)]
enum CipherType {
    AesGcm128 = 51,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct TlsCryptoInfo {
    version: TlsVersion,
    cipher_type: CipherType,
}

impl TlsCryptoInfo {
    fn new(protocol: &str, cipher_suite: &str) -> Result<Self, KTlsError> {
        match (protocol, cipher_suite) {
            ("TLSv1.2", "TLS_RSA_WITH_AES_128_GCM_SHA256") => Ok(Self {
                version: TlsVersion::Tls12,
                cipher_type: CipherType::AesGcm128,
            }),
            _ => Err(KTlsError::UnsupportedOperation {
                msg: format!(
                    "Unsupported: protocol={}, cipherSuite={}",
                    protocol, cipher_suite
                ),
            }),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct Tls12CryptoInfoAesGcm128 {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 16],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

fn expect_string(env: &JNIEnv, obj: JString) -> String {
    env.get_string(obj).expect("Failed to get JavaStr").into()
}

fn expect_byte_array(env: &JNIEnv, obj: jbyteArray) -> Vec<u8> {
    env.convert_byte_array(obj)
        .expect("Failed to convert to vec")
}

fn maybe_throw<T>(env: JNIEnv, res: &Result<T, KTlsError>) {
    if let Err(e) = res {
        println!("Error !! : {:?}", e);
        let (class, msg) = match e {
            KTlsError::Socket { msg } => (SOCKET_EXCEPTION_CLASS, msg),
            KTlsError::UnsupportedOperation { msg } => (UNSUPPORTED_OPERATION_EXCEPTION_CLASS, msg),
            KTlsError::IllegalArgument { msg } => (ILLEGAL_ARGUMENT_EXCEPTION_CLASS, msg),
        };
        env.throw_new(class, msg).expect("Failed to throw");
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mayreh_jktls_KTlsSocketChannel_setTcpUlp(
    env: JNIEnv,
    _class: JClass,
    fd: jint,
    name: JString,
) {
    maybe_throw(env, &set_tcp_ulp(env, fd, name));
}

fn set_tcp_ulp(env: JNIEnv, fd: jint, name: JString) -> Result<(), KTlsError> {
    let name = expect_string(&env, name);
    Errno::result(unsafe {
        setsockopt(
            fd,
            SOL_TCP,
            TCP_ULP,
            name.as_ptr() as *const c_void,
            name.len() as u32,
        )
    })
    .map(drop)
    .map_err(|e| KTlsError::Socket {
        msg: format!("Failed to set TCP_ULP: {}", e),
    })
}

#[no_mangle]
pub extern "system" fn Java_com_mayreh_jktls_KTlsSocketChannel_setTlsTx(
    env: JNIEnv,
    _class: JClass,
    fd: jint,
    protocol: JString,
    cipher_suite: JString,
    iv: jbyteArray,
    key: jbyteArray,
    salt: jbyteArray,
    rec_seq: jbyteArray,
) {
    maybe_throw(
        env,
        &set_tls_tx(env, fd, protocol, cipher_suite, iv, key, salt, rec_seq),
    )
}

#[allow(clippy::too_many_arguments)]
fn set_tls_tx(
    env: JNIEnv,
    fd: jint,
    protocol: JString,
    cipher_suite: JString,
    iv: jbyteArray,
    key: jbyteArray,
    salt: jbyteArray,
    rec_seq: jbyteArray,
) -> Result<(), KTlsError> {
    let protocol = expect_string(&env, protocol);
    let cipher_suite = expect_string(&env, cipher_suite);
    let info = TlsCryptoInfo::new(&protocol, &cipher_suite)?;
    let [iv, key, salt, rec_seq] = [iv, key, salt, rec_seq].map(|a| expect_byte_array(&env, a));

    let ret = match info {
        TlsCryptoInfo {
            version: TlsVersion::Tls12,
            cipher_type: CipherType::AesGcm128,
        } => {
            let crypt_info = Tls12CryptoInfoAesGcm128 {
                info,
                iv: iv.try_into().map_err(|_| KTlsError::IllegalArgument {
                    msg: "invalid iv".to_string(),
                })?,
                key: key.try_into().map_err(|_| KTlsError::IllegalArgument {
                    msg: "invalid key".to_string(),
                })?,
                salt: salt.try_into().map_err(|_| KTlsError::IllegalArgument {
                    msg: "invalid salt".to_string(),
                })?,
                rec_seq: rec_seq.try_into().map_err(|_| KTlsError::IllegalArgument {
                    msg: "invalid rec_seq".to_string(),
                })?,
            };
            unsafe {
                setsockopt(
                    fd,
                    SOL_TLS,
                    TLS_TX,
                    (&crypt_info) as *const Tls12CryptoInfoAesGcm128 as *const c_void,
                    size_of::<Tls12CryptoInfoAesGcm128>() as u32,
                )
            }
        }
    };
    Errno::result(ret).map(drop).map_err(|e| KTlsError::Socket {
        msg: format!("Failed to set TLS_TX: {}", e),
    })
}

#[no_mangle]
pub extern "system" fn Java_com_mayreh_jktls_KTlsSocketChannel_sendFile(
    env: JNIEnv,
    _class: JClass,
    out_fd: jint,
    in_fd: jint,
    position: jlong,
    count: jlong,
) -> jlong {
    let res = send_file(env, out_fd, in_fd, position, count);
    maybe_throw(env, &res);
    res.unwrap_or(-1)
}

#[allow(unused_variables)]
fn send_file(
    env: JNIEnv,
    out_fd: jint,
    in_fd: jint,
    mut position: jlong,
    count: jlong,
) -> Result<jlong, KTlsError> {
    #[cfg(target_os = "linux")]
    let res = nix::sys::sendfile::sendfile64(out_fd, in_fd, Some(&mut position), count as usize)
        .map(|c| c as jlong)
        .map_err(|e| KTlsError::Socket {
            msg: format!("Failed to sendfile: {}", e),
        });
    #[cfg(not(target_os = "linux"))]
    let res = Err(KTlsError::UnsupportedOperation {
        msg: "Currently only linux is supported".to_string(),
    });

    res
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
