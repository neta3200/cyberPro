from django.shortcuts import render, redirect
from django.http import HttpResponse
# Create your views here.

def loginRedirection(request, *args, **kwargs):
    response = redirect('/login')
    response.set_cookie('isSecure', "true")
    response.set_cookie('attemps_number', 0)
    response.set_cookie('isAuthenticated', "false")
    return response

def aboutPage(request, *args, **kwargs):
    my_context = {
        'title': 'About',
        'page_name': 'about',
    }
    return render(request, 'about.html', my_context)
