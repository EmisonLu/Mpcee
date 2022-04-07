package controllers

import (
	beego "github.com/beego/beego/v2/server/web"
	// "log"
)

type MainController struct {
	beego.Controller
}

func (c *MainController) Get() {
	// log.Printf(say_something("Hello, from untrust!"))
	c.Data["Website"] = "beego.me"
	c.Data["Email"] = "astaxie@gmail.com"
	c.TplName = "index.html"
}
