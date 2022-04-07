package main

import (
	_ "server/routers"
	_ "server/models"

	beego "github.com/beego/beego/v2/server/web"
)

func main() {
	beego.Run()
}

