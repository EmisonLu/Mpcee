package controllers

import (
	// "encoding/base64"
	beego "github.com/beego/beego/v2/server/web"
)

type PsiController struct {
	beego.Controller
}

func (c *PsiController) Get() {
	if !c.Islogin() {
		c.Redirect("/login", 302)
	}

	c.TplName = "psi.html"
}