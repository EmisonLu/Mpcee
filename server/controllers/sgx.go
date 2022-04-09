package controllers

//#cgo LDFLAGS: -L${SRCDIR}/../../tee/app/target/release -L /opt/sgxsdk/lib64 -ltee -l sgx_urts -ldl -lm
//#include <stdint.h>
//#include <math.h>
//extern unsigned long long init_enclave();
//extern void rust_get_session_key(char* enc_pswd_from_db, size_t enc_pswd_from_db_len, char* enc_data, size_t enc_data_len, size_t* result_string_size);
//extern void rust_register(char* enc_user_pswd, size_t enc_user_pswd_len, char* user, size_t* user_len, char* enc_pswd, size_t* enc_pswd_len, size_t* result_string_size, size_t string_limit);
//extern void rust_user_logout( char* some_string, size_t some_len,size_t* result_string_size);
//extern void rust_server_hello( char* pk_n, size_t* pk_n_len, char* pk_e, size_t* pk_e_len, char* certificate, size_t* certificate_len, size_t string_limit);
import "C"

const STRING_LIMIT = 8192

func server_hello() (string, string, string) {
	pk_e := (*C.char)(C.malloc(STRING_LIMIT))
	pk_e_len := (C.ulong)(0)

	pk_n := (*C.char)(C.malloc(STRING_LIMIT))
	pk_n_len := (C.ulong)(0)

	Certificate := (*C.char)(C.malloc(STRING_LIMIT))
	Certificate_len := (C.ulong)(0)

	C.rust_server_hello(pk_n, &pk_n_len, pk_e, &pk_e_len, Certificate, &Certificate_len, STRING_LIMIT)

	public_key_n_str := C.GoStringN(pk_n, (C.int)(pk_n_len))
	public_key_e_str := C.GoStringN(pk_e, (C.int)(pk_e_len))
	Certificate_str := C.GoStringN(Certificate, (C.int)(Certificate_len))

	return public_key_n_str, public_key_e_str, Certificate_str
}

func register(enc_user_pswd string) (string, string) {
	enc_pswd := (*C.char)(C.malloc(STRING_LIMIT))
	enc_pswd_len := (C.ulong)(0)

	user := (*C.char)(C.malloc(STRING_LIMIT))
	user_len := (C.ulong)(0)

	success := (C.ulong)(0)

	C.rust_register(C.CString(enc_user_pswd), C.ulong(len(enc_user_pswd)),
		user, &user_len, enc_pswd, &enc_pswd_len, &success, STRING_LIMIT)

	if success == 0 {
		return "", ""
	}

	user_str := C.GoStringN(user, (C.int)(user_len))
	enc_pswd_str := C.GoStringN(enc_pswd, (C.int)(enc_pswd_len))
	return user_str, enc_pswd_str
}

func get_session_key(enc_pswd_from_db string, enc_data string) bool {
	success := (C.ulong)(0)
	C.rust_get_session_key(
		C.CString(enc_pswd_from_db), C.ulong(len(enc_pswd_from_db)),
		C.CString(enc_data), C.ulong(len(enc_data)),
		&success,
	)
	if success == 0 {
		return false
	}
	return true
}

func user_logout(input string) bool {
	success := (C.ulong)(0)
	C.rust_user_logout(C.CString(input), C.ulong(len(input)), &success)

	if success == 1 {
		return true
	}
	return false
}
