package controllers

import (
	beego "github.com/beego/beego/v2/server/web"
)

type MainController struct {
	beego.Controller
}

func (c *MainController) ShowIndex() {
	// if !c.Islogin() {
	// 	c.Redirect("/login", 302)
	// }

	c.TplName = "index.html"
}
