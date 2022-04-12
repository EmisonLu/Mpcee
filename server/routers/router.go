package routers

import (
	"server/controllers"
	beego "github.com/beego/beego/v2/server/web"
)

func init() {
	beego.Router("/", &controllers.MainController{}, "get:ShowIndex")

	beego.Router("/login", &controllers.LoginController{})
	beego.Router("/logout", &controllers.LogoutController{})
	beego.Router("/session_key", &controllers.SessionKeyController{})
	beego.Router("/register", &controllers.RegController{})
	beego.Router("/psi", &controllers.PsiController{})
}
