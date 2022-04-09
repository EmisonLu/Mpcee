package controllers

import (
	"encoding/base64"
	"fmt"
	"github.com/beego/beego/v2/client/orm"
	beego "github.com/beego/beego/v2/server/web"
	"server/models"
)

type RegController struct {
	beego.Controller
}

type LoginController struct {
	beego.Controller
}

type LogoutController struct {
	beego.Controller
}

func (c *RegController) Get() {
	c.TplName = "register.html"
}

func (c *RegController) Post() {
	ReturnData := make(map[string]interface{})

	userName := c.GetString("userName")
	enc_uname_pwd_base64 := c.GetString("enc_uname_pwd")

	_, enc_pswd_str := register(enc_uname_pwd_base64)

	enc_pswd_base64 := base64.StdEncoding.EncodeToString([]byte(enc_pswd_str))

	errMsg := CheckReg(userName, enc_pswd_base64)

	if errMsg != "" {
		ReturnData["message"] = errMsg
		ReturnData["res"] = "0"
	} else {
		ReturnData["res"] = "1"
		ReturnData["message"] = "0"
	}

	c.Data["json"] = ReturnData
	c.ServeJSON()
}

func CheckReg(userName string, passWd string) (errMsg string) {
	errMsg = ""
	o := orm.NewOrm()
	user := models.User{}
	user.Name = userName
	err := o.Read(&user, "Name")
	if err == nil && !user.Isdelete {
		errMsg = "The username is already taken!"
	} else {
		user.Passwd = passWd[0:255]
		user.Passwd_more = passWd[255:]
		user.Isactive = true
		user.Isdelete = false
		_, err = o.Insert(&user)
		if err != nil {
			errMsg = fmt.Sprint(err)
		}
	}
	return errMsg
}

func (c *LoginController) Get() {
	c.TplName = "login.html"
}

func (c *LoginController) Post() {
	ReturnData := make(map[string]interface{})

	userName := c.GetString("userName")
	enc_session_package_base64 := c.GetString("enc_session_package")

	enc_session_package, _ := base64.StdEncoding.DecodeString(enc_session_package_base64)

	errMsg := ""
	id := -1
	o := orm.NewOrm()
	user := models.User{}
	user.Name = userName
	err := o.Read(&user, "Name")
	if err != nil {
		errMsg = "Username does not exist!"
	} else if user.Isdelete {
		errMsg = "User is logged out!"
	} else {
		id = user.Id
	}

	pswd_base64 := user.Passwd + user.Passwd_more
	pswd, _ := base64.StdEncoding.DecodeString(pswd_base64)

	if errMsg == "" {
		if !get_session_key(string(pswd[:]), string(enc_session_package[:])) {
			errMsg = "Wrong password!"
		}
	}

	status := UserStatus{userName, id, true}
	c.SetSession("status", status)

	if errMsg == "" {
		ReturnData["res"] = "1"
		ReturnData["message"] = "0"
	} else {
		ReturnData["res"] = "0"
		ReturnData["message"] = errMsg
	}

	c.Data["json"] = ReturnData
	c.ServeJSON()
}

func (c *LogoutController) Get() {
	ReturnData := make(map[string]interface{})

	package_str := c.GetString("package_str")

	if c.Islogin() {
		status := c.GetSession("status").(UserStatus)
		status.islogin = false
		c.SetSession("status", status)
		if user_logout(package_str) {
			ReturnData["res"] = "1"
			ReturnData["message"] = "Logout success!"
		} else {
			ReturnData["res"] = "0"
			ReturnData["message"] = "Logout faliure!"
		}
	} else {
		ReturnData["res"] = "0"
		ReturnData["message"] = "Not logged in!"
	}

	c.Data["json"] = ReturnData
	c.ServeJSON()
}
