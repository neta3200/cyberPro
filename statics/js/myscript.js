// document.getElementById("mode-text").innerHTML = "new text mf!!!"

// const toggle_button = '#toggle-button';

f = true

function getCookie(cname) {
    let name = cname + "=";
    let decodedCookie = decodeURIComponent(document.cookie);
    let ca = decodedCookie.split(';');
    for(let i = 0; i <ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) == ' ') {
        c = c.substring(1);
      }
      if (c.indexOf(name) == 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
  }

function getSecureCookie() {
    var dc = document.cookie;
    return dc.split(';');
}

function setCookie(cname, cvalue, exdays = 2) {
    const d = new Date();
    d.setTime(d.getTime() + (exdays*24*60*60*1000));
    let expires = "expires="+ d.toUTCString();
    document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/;NULL,0";
  }

  function toggle_clicked(toggle_button){
    let toggle = document.getElementById("toggle-button");
    if (toggle.checked){
        setCookie('isSecure', 'true')
        secure_design();
        secure_clients_page();
        secure_login_page();
        secure_register_page()
        console.log("toggle set to secure!!");
        clearURL();
        
        
    } else {
        console.log("toggle set to insecure!!");
        setCookie('isSecure', 'false');
        insecure_design();
        insecure_clients_page();
        insecure_login_page();
        insecure_register_page()
    }

};

function update_toggle(){
    console.log(getCookie('isSecure'))
    if (getCookie('isSecure') == 'true'){
        document.getElementById("toggle-button").setAttribute("checked", "checked");
        secure_design();
        secure_clients_page();
        secure_login_page();
        secure_register_page()
    } else{
        document.getElementById("toggle-button").removeAttribute("checked");
        insecure_design();
        insecure_clients_page();
        insecure_login_page();
        insecure_register_page();
    }

}


function secure_design(){
    document.getElementById('topnav').classList.remove("insecure")
    document.getElementById('topnav').classList.add("secure")
    document.getElementById('mode-text').innerHTML = "Mode: Secure";
}

function insecure_design(){
    document.getElementById('topnav').classList.remove("secure")
    document.getElementById('topnav').classList.add("insecure")
    document.getElementById('mode-text').innerHTML = "Mode: Insecure";
}

function secure_clients_page(){
    var insecureForm = document.getElementById("insecure-form");
    var secureForm = document.getElementById("secure-form");
    if (insecureForm !== null) {
        insecureForm.style.display = "none";
    }
    if (secureForm !== null) {
        secureForm.style.display = "block";
    }
}

function insecure_clients_page(){
    var insecureForm = document.getElementById("insecure-form");
    var secureForm = document.getElementById("secure-form");
    if (insecureForm !== null) {
        insecureForm.style.display = "block";
    }
    if (secureForm !== null) {
        secureForm.style.display = "none";
    }
}


function secure_login_page(){
    var insecureForm = document.getElementById("insecure-form-login");
    var secureForm = document.getElementById("secure-form-login");

    if (insecureForm !== null) {
        insecureForm.style.display = "none";
    }
    if (secureForm !== null) {
        secureForm.style.display = "block";
    }
}

function secure_register_page(){
    var insecureForm = document.getElementById("insecure-form-register");
    var secureForm = document.getElementById("secure-form-register");

    if (insecureForm !== null) {
        insecureForm.style.display = "none";
    }
    if (secureForm !== null) {
        secureForm.style.display = "block";
    }
} 


function insecure_login_page(){
    var insecureForm = document.getElementById("insecure-form-login");
    var secureForm = document.getElementById("secure-form-login");

    if (insecureForm !== null) {
        insecureForm.style.display = "block";
    }
    if (secureForm !== null) {
        secureForm.style.display = "none";
    }
}

function insecure_register_page(){
    var insecureForm = document.getElementById("insecure-form-register");
    var secureForm = document.getElementById("secure-form-register");

    if (insecureForm !== null) {
        insecureForm.style.display = "block";
    }
    if (secureForm !== null) {
        secureForm.style.display = "none";
    }
}


function clearURL(){
    let currentURL = document.URL
    window.location.assign(currentURL.split('?')[0])

}

update_toggle();
