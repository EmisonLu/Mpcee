function register() {
    'use strict';

    var uname = document.getElementById('userName').value;
    var pwd = document.getElementById('passWd').value;
    var pwd_2 = document.getElementById('passWd_2').value;

    if (typeof uname == "undefined" || uname == null || uname == "") {
        alert("Username can't be empty!");
        window.location.href = '/register';
        return;
    }
    if (typeof pwd == "undefined" || pwd == null || pwd == "") {
        alert("Password can't be empty!");
        window.location.href = '/register';
        return;
    }
    if (pwd.length < 8) {
        alert("Password must be at least 8 characters long!");
        window.location.href = '/register';
        return;
    }
    if (pwd !== pwd_2) {
        alert("The two password entries are inconsistent!");
        window.location.href = '/register';
        return;
    }

    $.ajax({
        url: "/register",
        async: false,
        method: 'POST',
        data: { "userName": uname, "pwd": pwd },
        success: function (data) {
            console.log(data);
            console.log(data.res);
            console.log(data.message);
            if (data.res === "1") {
                window.location.assign("login.html");
                return;
            } else {
                alert(data.message);
                window.location.href = '/register';
                return;
            }
        }
    });

    window.location.href = '/login'
}