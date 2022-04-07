package routers

import (
	"server/controllers"
	beego "github.com/beego/beego/v2/server/web"
)

func init() {
    beego.Router("/", &controllers.MainController{})

	beego.Router("/login", &controllers.UserLoginController{})
	beego.Router("/register", &controllers.UserRegController{})
	beego.Router("/logout", &controllers.UserLogoutController{})
	
}
