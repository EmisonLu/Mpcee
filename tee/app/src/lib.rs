extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;

extern crate lazy_static;
use lazy_static::lazy_static;
use std::ptr;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
lazy_static! {
    static ref SGX_ENCLAVE: SgxResult<SgxEnclave> = init_enclave();
}

extern "C" {
    fn server_hello(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        ref_tmp_pk_n: *const u8,
        len_tmp_pk_n: &mut usize,
        ref_tmp_pk_e: *const u8,
        len_tmp_pk_e: &mut usize,
        ref_tmp_certificate: *const u8,
        len_tmp_certificate: &mut usize,
        string_limit: usize,
    ) -> sgx_status_t;

    fn user_register(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        enc_user_pswd: *const u8,
        enc_user_pswd_len: usize,
        user: *const u8,
        user_len: &mut usize,
        enc_pswd: *const u8,
        enc_pswd_len: &mut usize,
        string_limit: usize,
    ) -> sgx_status_t;

    fn get_session_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        enc_pswd_from_db: *const u8,
        enc_pswd_from_db_len: usize,
        enc_data: *const u8,
        enc_data_len: usize,
    ) -> sgx_status_t;

    fn user_logout(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        package_data: *const u8,
        package_data_len: usize,
    ) -> sgx_status_t;

    fn psi_upload(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        line: *const u8,
        len: usize,
    ) -> sgx_status_t;

    fn psi_compute(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        line: *const u8,
        len: usize,
        encrypted_result_string: *const u8,
        result_max_len: usize,
    ) -> sgx_status_t;
}

#[no_mangle]
pub extern "C" fn init_enclave() -> SgxResult<SgxEnclave> {
    println!("init_enclave");

    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;

    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };

    let x = SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    );
    match &x {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
        }
        Err(y) => {
            eprintln!("[-] Init Enclave Failed {}!", y.as_str());
        }
    };
    println!("init_enclave_finished");
    x
}

#[no_mangle]
pub extern "C" fn rust_init_enclave(success: *mut usize) -> Result<(), std::io::Error> {
    if let Err(_) = &*SGX_ENCLAVE {
        unsafe {
            *success = 0;
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "init enclave failed",
        ));
    }
    unsafe {
        *success = 1;
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn rust_server_hello(
    pk_n: *mut u8,
    pk_n_len: *mut usize,
    pk_e: *mut u8,
    pk_e_len: *mut usize,
    certificate: *mut u8,
    certificate_len: *mut usize,
    string_limit: usize,
) -> Result<(), std::io::Error> {
    let enclave = match &*SGX_ENCLAVE {
        Ok(r) => {
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "init enclave failed",
            ));
        }
    };

    let mut tmp_pk_n: Vec<u8> = vec![0; string_limit];
    let mut tmp_pk_e: Vec<u8> = vec![0; string_limit];
    let mut tmp_certificate: Vec<u8> = vec![0; string_limit];

    let ref_tmp_pk_n = &mut tmp_pk_n[..];
    let ref_tmp_pk_e = &mut tmp_pk_e[..];
    let ref_tmp_certificate = &mut tmp_certificate[..];

    let enclave_id = enclave.geteid();
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let mut len_tmp_pk_n: usize = 0;
    let mut len_tmp_pk_e: usize = 0;
    let mut len_tmp_certificate: usize = 0;

    let result = unsafe {
        server_hello(
            enclave_id,
            &mut retval,
            ref_tmp_pk_n.as_mut_ptr(),
            &mut len_tmp_pk_n,
            ref_tmp_pk_e.as_mut_ptr(),
            &mut len_tmp_pk_e,
            ref_tmp_certificate.as_mut_ptr(),
            &mut len_tmp_certificate,
            string_limit,
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            eprintln!("[-] ECALL Enclave Failed {}!", result.as_str());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "ecall failed",
            ));
        }
    }
    
    match retval {
        sgx_status_t::SGX_SUCCESS => {}
        e => {
            eprintln!("[-] ECALL Enclave Failed {}!", retval.as_str());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    }

    unsafe {
        *pk_n_len = len_tmp_pk_n;
        ptr::copy_nonoverlapping(ref_tmp_pk_n.as_ptr(), pk_n, *pk_n_len);
        *pk_e_len = len_tmp_pk_e;
        ptr::copy_nonoverlapping(ref_tmp_pk_e.as_ptr(), pk_e, *pk_e_len);
        *certificate_len = len_tmp_certificate;
        ptr::copy_nonoverlapping(ref_tmp_certificate.as_ptr(), certificate, *certificate_len);
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn rust_register(
    enc_user_pswd: *const u8,
    enc_user_pswd_len: usize,
    user: *mut u8,
    user_len: *mut usize,
    enc_pswd: *mut u8,
    enc_pswd_len: *mut usize,
    success: *mut usize,
    string_limit: usize,
) -> Result<(), std::io::Error> {
    let enc_vec: &[u8] = unsafe { std::slice::from_raw_parts(enc_user_pswd, enc_user_pswd_len) };
    let enc_data = String::from_utf8(enc_vec.to_vec()).unwrap();

    let enclave = match &*SGX_ENCLAVE {
        Ok(r) => {
            r
        }
        Err(x) => {
            println!("[-] rust register failled {}!", x.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "init enclave failed",
            ));
        }
    };
    let mut user_vec: Vec<u8> = vec![0; string_limit];
    let mut enc_pswd_vec: Vec<u8> = vec![0; string_limit];

    let tmp_user = &mut user_vec[..];
    let tmp_enc_pswd = &mut enc_pswd_vec[..];

    let mut tmp_user_len: usize = 0;
    let mut tmp_enc_pswd_len: usize = 0;

    let enclave_id = enclave.geteid();
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        user_register(
            enclave_id,
            &mut retval,
            enc_data.as_ptr() as *const u8,
            enc_data.len(),
            tmp_user.as_mut_ptr(),
            &mut tmp_user_len,
            tmp_enc_pswd.as_mut_ptr(),
            &mut tmp_enc_pswd_len,
            string_limit,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            eprintln!("[-] ECALL Enclave Failed {}!", result.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "ecall failed",
            ));
        }
    }
    match retval {
        sgx_status_t::SGX_SUCCESS => {}
        e => {
            eprintln!("[-] ECALL Enclave Failed {}!", retval.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    }

    unsafe {
        *user_len = tmp_user_len;
        *enc_pswd_len = tmp_enc_pswd_len;
        ptr::copy_nonoverlapping(tmp_user.as_ptr(), user, *user_len);
        ptr::copy_nonoverlapping(tmp_enc_pswd.as_ptr(), enc_pswd, *enc_pswd_len);
        *success = 1;
    }

    unsafe {
        *success = 1;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn rust_get_session_key(
    enc_pswd_from_db: *const u8,
    enc_pswd_from_db_len: usize,
    enc_data: *const u8,
    enc_data_len: usize,
    success: *mut usize,
) -> Result<(), std::io::Error> {
    let enclave = match &*SGX_ENCLAVE {
        Ok(r) => {
            r
        }
        Err(x) => {
            eprintln!("[-] Init Enclave Failed {}!", x.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "init enclave failed",
            ));
        }
    };
    let enclave_id = enclave.geteid();

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        get_session_key(
            enclave_id,
            &mut retval,
            enc_pswd_from_db,
            enc_pswd_from_db_len,
            enc_data,
            enc_data_len,
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            eprintln!("[-] ECALL Enclave Failed {}!", result.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "ecall failed",
            ));
        }
    }
    match retval {
        sgx_status_t::SGX_SUCCESS => {}
        e => {
            eprintln!("[-] ECALL Enclave Failed {}!", retval.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    }
    unsafe {
        *success = 1;
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn rust_user_logout(
    some_string: *const u8,
    some_len: usize,
    success: *mut usize,
) -> Result<(), std::io::Error> {
    let v: &[u8] = unsafe { std::slice::from_raw_parts(some_string, some_len) };
    let line = String::from_utf8(v.to_vec()).unwrap();

    let enclave = match &*SGX_ENCLAVE {
        Ok(r) => {
            r
        }
        Err(x) => {
            eprintln!("[-] Init Enclave Failed {}!", x.as_str());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "init enclave failed",
            ));
        }
    };
    let enclave_id = enclave.geteid();
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        user_logout(
            enclave_id,
            &mut retval,
            line.as_ptr() as *const u8,
            line.len(),
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            eprintln!("[-] ECALL Enclave Failed {}!", result.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "ecall failed",
            ));
        }
    }
    match retval {
        sgx_status_t::SGX_SUCCESS => {}
        e => {
            eprintln!("[-] ECALL Enclave Failed {}!", retval.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    }

    unsafe {
        *success = 1;
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn rust_psi_upload(
    some_string: *const u8,
    some_len: usize,
    success: *mut usize,
) -> Result<(), std::io::Error> {
    let v: &[u8] = unsafe { std::slice::from_raw_parts(some_string, some_len) };
    let line = String::from_utf8(v.to_vec()).unwrap();

    let enclave = match &*SGX_ENCLAVE {
        Ok(r) => {
            r
        }
        Err(x) => {
            eprintln!("[-] Init Enclave Failed {}!", x.as_str());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "init enclave failed",
            ));
        }
    };

    let enclave_id = enclave.geteid();

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        psi_upload(
            enclave_id,
            &mut retval,
            line.as_ptr() as *const u8,
            line.len(),
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            eprintln!("[-] ECALL Enclave Failed {}!", result.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "build ecall failed",
            ));
        }
    }
    match retval {
        sgx_status_t::SGX_SUCCESS => {}
        e => {
            eprintln!("[-] ECALL Enclave Failed {}!", retval.as_str());
            unsafe {
                *success = 0;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    }

    unsafe {
        *success = 1;
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn rust_psi_compute(
    user_string: *const u8,
    user_len: usize,
    result_string_limit: usize,
    encrypted_result_string: *mut u8,
    encrypted_result_string_size: *mut usize,
) -> Result<(), std::io::Error> {
    let v: &[u8] = unsafe { std::slice::from_raw_parts(user_string, user_len) };
    let line = String::from_utf8(v.to_vec()).unwrap();

    let enclave = match &*SGX_ENCLAVE {
        Ok(r) => {
            r
        }
        Err(x) => {
            eprintln!("[-] Init Enclave Failed {}!", x.as_str());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "init enclave failed",
            ));
        }
    };
    let enclave_id = enclave.geteid();

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let mut encrypted_result_vec: Vec<u8> = vec![0; result_string_limit];
    let encrypted_result_slice = &mut encrypted_result_vec[..];

    let result = unsafe {
        psi_compute(
            enclave_id,
            &mut retval,
            line.as_ptr() as *const u8,
            line.len(),
            encrypted_result_slice.as_mut_ptr(),
            result_string_limit,
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            eprintln!("[-] ECALL Enclave Failed {}!", result.as_str());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "ecall failed",
            ));
        }
    }

    match retval {
        sgx_status_t::SGX_SUCCESS => {}
        e => {
            eprintln!("[-] ECALL Enclave Failed {}!", retval.as_str());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    }

    let mut encrypted_result_vec: Vec<u8> = encrypted_result_slice.to_vec();
    encrypted_result_vec.retain(|x| *x != 0x00u8);
    if encrypted_result_vec.len() == 0 {
        println!("emptyString");
    } else {
        let raw_result_str = String::from_utf8(encrypted_result_vec).unwrap();
        let l = raw_result_str.len();
        if l > result_string_limit {
            panic!("{} > {}", l, result_string_limit);
        }
        unsafe {
            *encrypted_result_string_size = l;
            ptr::copy_nonoverlapping(
                raw_result_str.as_ptr(),
                encrypted_result_string,
                raw_result_str.len(),
            );
        }
    }

    Ok(())
}
