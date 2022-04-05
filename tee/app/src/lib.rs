extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;

use lazy_static::lazy_static;
extern crate lazy_static;

use std::ptr;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
lazy_static! {
    static ref SGX_ENCLAVE: SgxResult<SgxEnclave> = init_enclave();
}

extern "C" {
    // just use for test
    fn sgx_say_something(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        some_string: *const u8,
        len: usize,
        result: *const u8,
        result_max_len: usize,
    ) -> sgx_status_t;
}

#[no_mangle]
pub extern "C" fn init_enclave() -> SgxResult<SgxEnclave> {
    println!("init_enclave");

    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
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
pub extern "C" fn rust_init_enclave(
    success: *mut usize,
) -> Result<(), std::io::Error> {

    match &*SGX_ENCLAVE {
        Ok(r) => {
        }
        Err(x) => {
            unsafe{ *success = 0; }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "init enclave failed",
            ));
        }
    };

    unsafe{ *success = 1; }

    Ok(())
}

#[no_mangle]
pub extern "C" fn say_something_rs(
    some_string: *const u8,
    some_len: usize,
    result_string_limit: usize,
    result_string: *mut u8,
    result_string_size: *mut usize,
) -> Result<(), std::io::Error> {
    let s: &[u8] = unsafe { std::slice::from_raw_parts(some_string, some_len) };
    let s = String::from_utf8(s.to_vec()).unwrap();
    println!("{}", s);

    let enclave = match &*SGX_ENCLAVE {
        Ok(r) => r,
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

    let mut result_vec: Vec<u8> = vec![0; result_string_limit];
    let result_slice = &mut result_vec[..];

    let result = unsafe {
        sgx_say_something(
            enclave_id,
            &mut retval,
            s.as_ptr() as *const u8,
            s.len(),
            result_slice.as_mut_ptr(),
            result_string_limit,
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            eprintln!("[-] ECALL Enclave Failed {}!", result.as_str());
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    }

    let mut result_vec: Vec<u8> = result_slice.to_vec();
    result_vec.retain(|x| *x != 0x00u8);
    if result_vec.len() == 0 {
        println!("emptyString");
    } else {
        let raw_result_str = String::from_utf8(result_vec).unwrap();
        let l = raw_result_str.len();
        if l > result_string_limit {
            panic!("{} > {}", l, result_string_limit);
        }
        unsafe {
            *result_string_size = l;
            ptr::copy_nonoverlapping(raw_result_str.as_ptr(), result_string, raw_result_str.len());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        let s = init_sgx();
        println!("{:?}", s);
    }
}
