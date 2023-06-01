from django.http import response
from django.shortcuts import redirect, render

from django.http import Http404

from .models import Client


def clientCreation(request):

    res = None

    if request.method == 'GET':
        clientFirstName = request.GET.get('fname', None)
        clientLastName = request.GET.get('lname', None)
        clientInternetSpeed = request.GET.get('internetspeed', None)
    else:
        clientFirstName = request.POST.get('fname')
        clientLastName = request.POST.get('lname')
        clientInternetSpeed = request.POST.get('internetspeed')
        if not (clientFirstName.replace(' ', '').isalpha()) or not (clientLastName.replace(' ', '').isalpha()) or not (clientInternetSpeed.replace(' ', '').isdigit()): 
            return render (request, 'http404.html')

    if  clientFirstName and clientLastName and clientInternetSpeed:
        saveclient = Client(name= clientFirstName,lastName= clientLastName, internetSpeed=clientInternetSpeed)
        saveclient.save()
    
        if request.COOKIES['isSecure'] == 'true':
            sqlLastClientQuery = "SELECT * FROM clients_client order by id DESC LIMIT 1;"
            res = Client.objects.raw(sqlLastClientQuery)

        else:
            sqlClientQuery = f"SELECT * FROM clients_client WHERE name = '%s'  AND lastName = '%s';" % (clientFirstName, clientLastName)
            res = Client.objects.raw(sqlClientQuery)
            
    else:
        sqlLastClientQuery = "SELECT * FROM clients_client order by id DESC LIMIT 1;"
        res = Client.objects.raw(sqlLastClientQuery)


    context = {
        'page_name': 'clients',
        'client_fname': clientFirstName,
        'client_lname': clientLastName,
        'client_internetspeed': clientInternetSpeed,
        'isSecure': request.COOKIES['isSecure'],
        'title': 'Clients',
        'c': res
    }

    return render(request, "clients/clientCreation.html", context)
