package controllers

import (
	// "encoding/base64"
	"time"
	"fmt"
	"github.com/beego/beego/v2/client/orm"
	"server/models"
	beego "github.com/beego/beego/v2/server/web"
)

type PsiController struct {
	beego.Controller
}

type PsiSearchController struct {
	beego.Controller
}

type PsiCheckController struct {
	beego.Controller
}

func (c *PsiController) Get() {
	if !c.Islogin() {
		c.Redirect("/login", 302)
	}

	c.TplName = "psi.html"
}

func (c *PsiSearchController) Post() {
	if !c.Islogin() {
		c.Redirect("/login", 302)
	}

	ReturnData := make(map[string]interface{})

	initiator := c.GetString("initiator")
	participant := c.GetString("participant")
	search_user := ""

	fmt.Println(c.GetString("flag"))

	if c.GetString("flag") == "0" {
		search_user = initiator
	} else {
		search_user = participant
	}

	fmt.Println(search_user)

	errMsg := ""
	o := orm.NewOrm()
	user := models.User{}
	user.Name = search_user
	err := o.Read(&user, "Name")
	if err != nil {
		errMsg = "User does not exist!"
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

func (c *PsiCheckController) Post() {
	if !c.Islogin() {
		c.Redirect("/login", 302)
	}

	ReturnData := make(map[string]interface{})

	user1 := c.GetString("user1")
	user2 := c.GetString("user2")

	fmt.Println(user1, user2)

	psi_map[user1] = user2;
	times := 1

    for ; times <= 20; times++ {
        user, ok := psi_map[user2]

		if ok == false {
			time.Sleep(time.Duration(1)*time.Second)
			continue
		}

		if user == user1 {
			ReturnData["res"] = "1"
			ReturnData["message"] = "0"
			break
		} else {
			ReturnData["res"] = "0"
			ReturnData["message"] = "Initiator and participant do not match!"
			delete(psi_map, user1)
			break
		}
    }

	if times == 21 {
		ReturnData["res"] = "0"
		ReturnData["message"] = "Time out!"
		delete(psi_map, user1)
	}

	c.Data["json"] = ReturnData
	c.ServeJSON()
}