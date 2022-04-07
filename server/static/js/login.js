function login() {
    'use strict';

    var uname = document.getElementById('userName').value;
    var pwd = document.getElementById('passWd').value;

    if (typeof uname == "undefined" || uname == null || uname == "") {
        alert("Username can't be empty!");
        window.location.href = '/login';
        return;
    }
    if (typeof pwd == "undefined" || pwd == null || pwd == "") {
        alert("Password can't be empty!");
        window.location.href = '/login';
        return;
    }

    $.ajax({
        url: "/login",
        method: "POST",
        async: false,
        data: { "userName": uname, "pwd": pwd },
        success: function (data) {
            if (data.res === "1") {
                window.location.href = '/';
                return;
            } else {
                alert(data.message);
                window.location.href = '/login';
                return;
            }
        }
    });
}