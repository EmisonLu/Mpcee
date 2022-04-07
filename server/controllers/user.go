package controllers

import (
	// "encoding/base64"
	"fmt"
	"server/models"

	"github.com/beego/beego/v2/client/orm"
	// "github.com/beego/beego/v2/core/validation"
	beego "github.com/beego/beego/v2/server/web"
)

type UserLoginController struct {
	beego.Controller
}

type UserRegController struct {
	beego.Controller
}

type UserLogoutController struct {
	beego.Controller
}

func (c *UserLoginController) Get() {
	c.TplName = "login.html"
}

func (c *UserLoginController) Post() {
	ReturnData := make(map[string]interface{})

	userName := c.GetString("userName")
	pwd := c.GetString("pwd")
	
	errMsg := ""
	// id := -1
	o := orm.NewOrm()
	user := models.User{}
	user.Name = userName
	err := o.Read(&user, "Name")
	if err != nil {
		errMsg = "Username does not exist!"
	} else {
		// id = user.Id
		if user.Passwd_1 != pwd {
			errMsg = "Wrong password!"
		} else {
			// status := UserStatus{userName, id, true}
			// c.SetSession("status", status)
		}
	}

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

func (c *UserRegController) Get() {
	c.TplName = "register.html"
}

func (c *UserRegController) Post() {
	ReturnData := make(map[string]interface{})

	userName := c.GetString("userName")
	pwd := c.GetString("pwd")

	errMsg := ""

	o := orm.NewOrm()
	user := models.User{}
	user.Name = userName
	err := o.Read(&user, "Name")
	if err == nil {
		errMsg = "The username is already taken!"
	} else {
		user.Passwd_1 = pwd
		_, err = o.Insert(&user)
		if err != nil {
			errMsg = fmt.Sprint(err)
		}
	}
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

func (c *UserLogoutController) Get() {
	c.TplName = "index.html"
}