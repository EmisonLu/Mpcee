package controllers

//#cgo LDFLAGS: -L${SRCDIR}/../../tee/app/target/release -L /opt/sgxsdk/lib64 -ltee -l sgx_urts -ldl -lm
//#include <stdint.h>
//#include <math.h>
//extern void say_something_rs(char* some_string, size_t some_len, size_t result_string_limit, char* result_string, size_t* result_string_size);
import "C"

func say_something(input string) string {

	const result_string_limit = 8192
	a := C.CString(input)

	res := (*C.char)(C.malloc(result_string_limit))
	res_len := (C.ulong)(0)

	C.say_something_rs(a, C.ulong(len(input)), result_string_limit, res, &res_len)

	return C.GoStringN(res, (C.int)(res_len))
}