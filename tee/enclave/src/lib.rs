#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

extern crate rsa;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};

extern crate num_bigint;
use num_bigint::BigUint;

extern crate rand;
use rand::SeedableRng;

extern crate crypto;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer, symmetriccipher};

extern crate lazy_static;
use lazy_static::lazy_static;

extern crate serde;
use serde::{Deserialize, Serialize};

extern crate base64;

use std::{
    collections::HashMap, ptr, slice, string::String, string::ToString, sync::SgxMutex as Mutex,
    vec::Vec,
    thread,
    time::Duration
};

extern crate sgx_trts;
extern crate sgx_types;
use sgx_types::*;

#[derive(Serialize, Deserialize, Debug)]
struct G {
    a: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Package {
    user: String,
    data: String,
    user2: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PackagePsiCompute {
    user: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserInfo {
    user: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SessionKeyPackage {
    user: String,
    password: String,
    key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RawInput {
    data: String,
    common: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Items {
    a: std::vec::Vec<Item>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Item {
    data1: String,
    common: String,
    data2: String,
}

lazy_static! {
    static ref KEYMAP: Mutex<HashMap<String, [u8; 32]>> = Mutex::new(HashMap::new());

    static ref PSIMAP: Mutex<HashMap<String, Vec<RawInput>>> = Mutex::new(HashMap::new());
    static ref PSIRESMAP: Mutex<HashMap<String, Items>> = Mutex::new(HashMap::new());
    
    static ref PRIVATE_KEY: RSAPrivateKey = {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let bits = 2048;
        RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key")
    };
    static ref PUBLIC_KEY: RSAPublicKey = RSAPublicKey::from(&*PRIVATE_KEY);
    static ref PUBLIC_KEY_N: Vec<u8> = (*PUBLIC_KEY).n_to_vecu8();
    static ref PUBLIC_KEY_E: Vec<u8> = (*PUBLIC_KEY).e_to_vecu8();
    static ref CERTIFICATE: Vec<u8> = get_from_CA();
}

fn decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 8192];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

#[warn(improper_ctypes_definitions)]
extern "C" fn sgx_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
    requester: &String,
) -> Result<String, String> {
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };
    let key: [u8; 32] = (*KEYMAP).lock().unwrap().get(requester).unwrap().clone();

    let iv: [u8; 16] = [0; 16];
    let w = base64::decode(ciphertext_slice);
    match w {
        Err(base64::DecodeError::InvalidByte(a, b)) => {
            eprintln!("InvalidByte {} {}", a, b);
            return Err("InvalidByte".to_string());
        }
        Err(base64::DecodeError::InvalidLength) => {
            eprintln!("InvalidLength");
            return Err("InvalidLength".to_string());
        }
        Err(base64::DecodeError::InvalidLastSymbol(a, b)) => {
            eprintln!("InvalidLastSymbol {} {}", a, b);
            return Err("InvalidLastSymbol".to_string());
        }
        Ok(_) => {}
    }
    let z = w.unwrap();

    let mut x = match decrypt(&z[..], &key, &iv) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("decrpyt error");
            return Err("InvalidByte".to_string());
        }
    };
    for i in 0..(x.len()) {
        if x[i] < 32 {
            x[i] = 32;
        }
    }
    let y: &str = std::str::from_utf8(&x).unwrap();
    let g: G = serde_json::from_str(&y).unwrap();
    Ok(g.a)
}

fn encrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 8192];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

pub fn str2aes2base64(message: &str, requester: &String) -> String {
    let g: G = G {
        a: message.to_string(),
    };
    let y = serde_json::to_string(&g).unwrap();

    let key: [u8; 32] = (*KEYMAP).lock().unwrap().get(requester).unwrap().clone();
    let iv: [u8; 16] = [0; 16];

    let x: Vec<u8> = encrypt(y.as_bytes(), &key, &iv).ok().unwrap();

    base64::encode(&x)
}

fn get_from_CA() -> Vec<u8> {
    let cer = b"wo shi hao ren";
    cer.to_vec()
}

#[no_mangle]
pub extern "C" fn server_hello(
    ref_tmp_pk_n: *mut u8,
    len_tmp_pk_n: &mut usize,
    ref_tmp_pk_e: *mut u8,
    len_tmp_pk_e: &mut usize,
    ref_tmp_certificate: *mut u8,
    len_tmp_certificate: &mut usize,
    string_limit: usize,
) -> sgx_status_t {
    let public_key_n_str = BigUint::from_bytes_le(&*PUBLIC_KEY_N).to_string();
    let public_key_e_str = BigUint::from_bytes_le(&*PUBLIC_KEY_E).to_string();

    *len_tmp_pk_n = public_key_n_str.len();
    *len_tmp_pk_e = public_key_e_str.len();
    *len_tmp_certificate = (*CERTIFICATE).len();

    if public_key_n_str.len() < string_limit
        && public_key_e_str.len() < string_limit
        && (*CERTIFICATE).len() < string_limit
    {
        unsafe {
            ptr::copy_nonoverlapping(
                public_key_n_str.as_ptr(),
                ref_tmp_pk_n,
                public_key_n_str.len(),
            );
            ptr::copy_nonoverlapping(
                public_key_e_str.as_ptr(),
                ref_tmp_pk_e,
                public_key_e_str.len(),
            );
            ptr::copy_nonoverlapping(
                (*CERTIFICATE).as_ptr(),
                ref_tmp_certificate,
                (*CERTIFICATE).len(),
            );
        }
    } else {
        eprintln!("Public key len > buf size",);
        return sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT;
    }

    return sgx_status_t::SGX_SUCCESS;
}

#[no_mangle]
pub extern "C" fn user_register(
    enc_user_pswd: *const u8,
    enc_user_pswd_len: usize,
    user: *mut u8,
    user_len: &mut usize,
    enc_pswd: *mut u8,
    enc_pswd_len: &mut usize,
    string_limit: usize,
) -> sgx_status_t {
    let enc_vec: &[u8] = unsafe { std::slice::from_raw_parts(enc_user_pswd, enc_user_pswd_len) };

    let w: &[u8] = &base64::decode(enc_vec).unwrap();

    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let user_data_vec = match (*PRIVATE_KEY).decrypt(padding, w) {
        Ok(r) => r,
        _ => {
            println!("[-] session key decrypt ERROR!");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let user_data_string = String::from_utf8(user_data_vec.to_vec()).unwrap();

    let user_data: UserInfo = serde_json::from_str(&user_data_string).unwrap();
    let tmp_user = user_data.user;
    let tmp_pswd = user_data.password;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let tmp_enc_pswd = (*PUBLIC_KEY)
        .encrypt(&mut rng, padding, &tmp_pswd.as_bytes())
        .expect("failed to encrypt");

    if tmp_user.len() < string_limit && tmp_user.len() < string_limit {
        unsafe {
            *user_len = tmp_user.len();
            *enc_pswd_len = tmp_enc_pswd.len();
            ptr::copy_nonoverlapping(tmp_user.as_ptr(), user, tmp_user.len());
            ptr::copy_nonoverlapping(tmp_enc_pswd.as_ptr(), enc_pswd, tmp_enc_pswd.len());
        }
    } else {
        eprintln!("Result len > buf size",);
        return sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT;
    }

    return sgx_status_t::SGX_SUCCESS;
}

#[no_mangle]
pub extern "C" fn get_session_key(
    enc_pswd_from_db: *const u8,
    enc_pswd_from_db_len: usize,
    enc_data: *const u8,
    enc_data_len: usize,
) -> sgx_status_t {
    let enc_db_pswd_u8: &[u8] =
        unsafe { std::slice::from_raw_parts(enc_pswd_from_db, enc_pswd_from_db_len) };

    let enc_data_u8: &[u8] = unsafe { std::slice::from_raw_parts(enc_data, enc_data_len) };

    let db_pswd =
        match (*PRIVATE_KEY).decrypt(PaddingScheme::new_pkcs1v15_encrypt(), enc_db_pswd_u8) {
            Ok(r) => r,
            _ => {
                println!("[-] password from database decrypt ERROR!");
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        };

    let sk_data = match (*PRIVATE_KEY).decrypt(PaddingScheme::new_pkcs1v15_encrypt(), enc_data_u8) {
        Ok(r) => r,
        _ => {
            println!("[-] session key package decrypt ERROR!");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    let data_str;
    let db_pswd_str;
    unsafe {
        data_str = String::from_utf8_unchecked(sk_data.to_vec());
        db_pswd_str = String::from_utf8_unchecked(db_pswd.to_vec());
    };

    let data_struct: SessionKeyPackage = match serde_json::from_str(&data_str) {
        Ok(r) => r,
        _ => {
            println!("[-] package serde ERROR!");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    if db_pswd_str != data_struct.password {
        println!("[-] password ERROR!");
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let session_key = data_struct.key;
    if session_key.len() != 32 {
        println!("[-] session key length ERROR!");
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let sk_u8_vec: Vec<u8> = session_key.as_bytes().to_vec();

    let sk_ptr = sk_u8_vec.as_ptr() as *const [u8; 32];
    let sk = unsafe { &*sk_ptr };
    let sk: [u8; 32] = sk.clone();

    (*KEYMAP).lock().unwrap().insert(data_struct.user, sk);

    for (key, _) in (*KEYMAP).lock().unwrap().iter() {
        println!("key: {}", key);
    }

    return sgx_status_t::SGX_SUCCESS;
}

#[no_mangle]
pub extern "C" fn user_logout(some_string: *const u8, some_len: usize) -> sgx_status_t {
    let v: &[u8] = unsafe { std::slice::from_raw_parts(some_string, some_len) };
    let vraw = String::from_utf8(v.to_vec()).unwrap();
    let package_input: Package = serde_json::from_str(&vraw).unwrap();
    let requester = package_input.user;
    let enc_data = package_input.data;

    let x = sgx_decrypt(enc_data.as_ptr() as *const u8, enc_data.len(), &requester);

    if let Err(y) = x {
        eprintln!("sgx_decrypt failed: {:?}", y);
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    let user_name: String = x.unwrap();

    if !(*KEYMAP).lock().unwrap().contains_key(&user_name) {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    (*KEYMAP).lock().unwrap().remove(&user_name);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn psi_upload(some_string: *const u8, some_len: usize) -> sgx_status_t {
    let v: &[u8] = unsafe { std::slice::from_raw_parts(some_string, some_len) };
    let vraw = String::from_utf8(v.to_vec()).unwrap();  
    let package_input: Package = serde_json::from_str(&vraw).unwrap();
    let requester = package_input.user;
    let user = requester.clone();
    let user2 = package_input.user2;
    let enc_data = package_input.data;

    let x = sgx_decrypt(enc_data.as_ptr() as *const u8, enc_data.len(), &requester);

    if let Err(y) = x {
        eprintln!("sgx_decrypt failed: {:?}", y);
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let line1: String = x.unwrap();

    // let print_struct = Package{user:requester.clone(), data:line1.clone()[requester.len()+1..].to_string(), user2: user2.clone()};
    // println!("服务端可信区的明文数据: ");
    // println!("{:#?}", print_struct);
    // println!("=====================================\n\n\n");

    // let line1 = line.clone();
    let v: &[u8] = unsafe { std::slice::from_raw_parts(line1.as_ptr() as *const u8, line1.len()) };
    let mut v_vec = v.to_vec();
    for i in &mut v_vec {
        if *i < 32{
            *i = 32;
        }
    }

    let line = String::from_utf8(v_vec).unwrap();

    let raw_input: Vec<RawInput> = match serde_json::from_str(&line){
        Ok(r) => r,
        Err(_) =>{
            eprintln!("parse build package error.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    // println!("{:#?}", raw_input);

    (*PSIMAP).lock().unwrap().insert(requester, raw_input);

    for (key, value) in (*PSIMAP).lock().unwrap().iter() {
        println!("key: {}", key);
        println!("value: {:#?}", value);
    }

    let mut x = 0;
    while x != 20 {
        if !(*PSIMAP).lock().unwrap().contains_key(&user2) {
            x += 1;
            thread::sleep(Duration::from_millis(1000));
            continue;
        }
        break;
    }
    
    if x == 20 {
        (*PSIMAP).lock().unwrap().remove(&user);
        sgx_status_t::SGX_ERROR_UNEXPECTED
    } else {
        sgx_status_t::SGX_SUCCESS
    }    
}

#[no_mangle]
pub extern "C" fn psi_compute(
    some_string: *const u8,
    some_len: usize,
    encrypted_result_string: *mut u8,
    result_max_len: usize,
) -> sgx_status_t {
    let v: &[u8] = unsafe { std::slice::from_raw_parts(some_string, some_len) };
    let vraw = String::from_utf8(v.to_vec()).unwrap();  
    let package_input: PackagePsiCompute = serde_json::from_str(&vraw).unwrap();

    let requester = package_input.user;
    let enc_data = package_input.data;

    let x = sgx_decrypt(enc_data.as_ptr() as *const u8, enc_data.len(), &requester);

    if let Err(y) = x {
        eprintln!("sgx_decrypt failed: {:?}", y);
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    let user2: String = x.unwrap();

    let mut point = Items { a: vec![] };
    
    if (*PSIRESMAP).lock().unwrap().contains_key(&user2) {
        point = (*PSIRESMAP).lock().unwrap().get(&user2).unwrap().clone();
        (*PSIRESMAP).lock().unwrap().remove(&user2);
    } else {
        if !(*PSIMAP).lock().unwrap().contains_key(&requester) {
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }

        let user1_data = (*PSIMAP).lock().unwrap().get(&requester).unwrap().clone();
        let user2_data = (*PSIMAP).lock().unwrap().get(&user2).unwrap().clone();

        for val1 in user1_data {
            for val2 in user2_data.clone() {
                let RawInput{data: data1,common: common1}=val1.clone();
                let RawInput{data: data2,common: common2}=val2.clone();

                if common1 == common2 {
                    let g = Item {
                        data1: data1.to_string(),
                        common: common1.to_string(),
                        data2: data2.to_string(),
                    };
                    point.a.push(g);
                }
            }
        }

        (*PSIRESMAP).lock().unwrap().insert(requester.clone(), point.clone());
        (*PSIMAP).lock().unwrap().remove(&requester);
        (*PSIMAP).lock().unwrap().remove(&user2);
    }

    let x = serde_json::to_string(&point).unwrap();
    let encrypted_x = str2aes2base64(&x, &requester);

    if encrypted_x.len() < result_max_len {
        unsafe {
            // ptr::copy_nonoverlapping(x.as_ptr(), result_string, x.len());
            ptr::copy_nonoverlapping(
                encrypted_x.as_ptr(),
                encrypted_result_string,
                encrypted_x.len(),
            );
        }
        return sgx_status_t::SGX_SUCCESS;
    } else {
        eprintln!(
            "Result len = {} > buf size = {}",
            encrypted_x.len(),
            result_max_len
        );
        return sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT;
    }
}