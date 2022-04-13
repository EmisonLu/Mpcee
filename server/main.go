package main

//#cgo LDFLAGS: -L${SRCDIR}/../tee/app/target/release -L /opt/sgxsdk/lib64 -ltee -l sgx_urts -ldl -lm
//extern void rust_init_enclave(size_t* result);
import "C"

import (
	beego "github.com/beego/beego/v2/server/web"
	_ "server/models"
	_ "server/routers"
)

func main() {
	// if !enclave_init() {
	// 	return
	// }
	beego.BConfig.WebConfig.Session.SessionOn = true
	beego.Run("0.0.0.0:10001")
}

func enclave_init() bool {
	success := (C.ulong)(0)
	C.rust_init_enclave(&success)

	if success == 0 {
		return false
	}
	return true
}
