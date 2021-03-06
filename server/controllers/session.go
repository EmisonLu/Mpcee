package controllers

//这个结构体有问题，后面修
type UserStatus struct {
	userName string
	userid   int
	islogin  bool
}

var psi_map = make(map[string] string)

func (c *MainController) Islogin() bool {
	status := c.GetSession("status")
	if status == nil {
		c.Redirect("/login", 302)
	}
	return !(status == nil || (status != nil && !status.(UserStatus).islogin))
}

func (c *MainController) UserName() string {
	status := c.GetSession("status")
	if status == nil {
		c.Redirect("/login", 302)
	}
	return status.(UserStatus).userName
}

func (c *RegController) Islogin() bool {
	status := c.GetSession("status")
	if status == nil {
		c.Redirect("/login", 302)
	}
	return !(status == nil || (status != nil && !status.(UserStatus).islogin))
}

func (c *LogoutController) Islogin() bool {
	status := c.GetSession("status")
	if status == nil {
		c.Redirect("/login", 302)
	}
	return !(status == nil || (status != nil && !status.(UserStatus).islogin))
}

func (c *PsiController) Islogin() bool {
	status := c.GetSession("status")
	if status == nil {
		c.Redirect("/login", 302)
	}
	return !(status == nil || (status != nil && !status.(UserStatus).islogin))
}

func (c *PsiSearchController) Islogin() bool {
	status := c.GetSession("status")
	if status == nil {
		c.Redirect("/login", 302)
	}
	return !(status == nil || (status != nil && !status.(UserStatus).islogin))
}

func (c *PsiCheckController) Islogin() bool {
	status := c.GetSession("status")
	if status == nil {
		c.Redirect("/login", 302)
	}
	return !(status == nil || (status != nil && !status.(UserStatus).islogin))
}

func (c *PsiUploadController) Islogin() bool {
	status := c.GetSession("status")
	if status == nil {
		c.Redirect("/login", 302)
	}
	return !(status == nil || (status != nil && !status.(UserStatus).islogin))
}

func (c *PsiComputeController) Islogin() bool {
	status := c.GetSession("status")
	if status == nil {
		c.Redirect("/login", 302)
	}
	return !(status == nil || (status != nil && !status.(UserStatus).islogin))
}
