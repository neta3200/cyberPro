"""cyberpro URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
#from django.conf.urls import url
from django.urls import include, path
from django.contrib import admin
from django.contrib.auth import views as auth_views

from django.urls import path
from django.urls.conf import include
from pages.views import  aboutPage, loginRedirection
from users.views import  forgetPassword, sentEmail, successChangePassowrd, codeVerifcation

from users.views import reqLogin, register, changePassword, reqLogout, resetPassword

from clients.views import clientCreation

urlpatterns = [
    
    path('admin/', admin.site.urls),
    path('', loginRedirection),
    path('login/', reqLogin),
    path('register/', register),
    path('clients/', clientCreation),
    path('change-pwd/', changePassword),
    path('change-pwd/done', successChangePassowrd),
    path('forgot-pwd/', forgetPassword),
    path('forgot-pwd/sent/', sentEmail),
    path('verify-code/', codeVerifcation),
    path('reset-pwd/', resetPassword),
    path('about/', aboutPage),
    path('logout/', reqLogout)
    
]
