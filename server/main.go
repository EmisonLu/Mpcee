package main

import (
	_ "server/routers"
	_ "server/models"
	"github.com/astaxie/beego"
)

func main() {
	beego.Run()
}

