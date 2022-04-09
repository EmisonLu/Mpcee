package controllers

import (
	"encoding/base64"
	beego "github.com/beego/beego/v2/server/web"
)

type SessionKeyController struct {
	beego.Controller
}

func (c *SessionKeyController) Get() {
	public_key_n, public_key_e, certificate := server_hello()

	ReturnData := make(map[string]interface{})

	ReturnData["pk_n"] = public_key_n
	ReturnData["pk_e"] = public_key_e
	ReturnData["certificate"] = certificate

	c.Data["json"] = ReturnData
	c.ServeJSON()
	c.StopRun()
}

func (c *SessionKeyController) Post() {
	ReturnData := make(map[string]interface{})

	date := c.GetString("encrypted_session_key")

	encrypted_session_key, _ := base64.StdEncoding.DecodeString(date)

	// fmt.Println(encrypted_session_key)

	get_session_key("1", string(encrypted_session_key[:]))

	ReturnData["result"] = true

	c.Data["json"] = ReturnData
	c.ServeJSON()
	c.StopRun()
}
