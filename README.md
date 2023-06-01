# Communication-LTD

A project was developed for my computer security course HIT college.

## Students:
  - Netanel Eiluz 
  - Dolev Mizrahi
  - Maor hamay
  - Maor shmuel

- Complexity settings and requirements of the login passwords are in the configuration file - passwordRequirements.json.


Prepare in advanced: pip install django-extensions Werkzeug pip install pyOpenSSL

Windows Path for hosts file : C:\Windows\System32\drivers\etc
Linux: /etc/hosts add to hosts file in your system: 127.0.0.1 cyber

Run the Server with port https ( port 443 ) with the command:
 python manage.py runserver_plus 127.0.0.1:443 --cert-file certs/cyber.pem --key-file certs/cyberprivate.pem

How Startup new Environment: 
python manage.py makemigrations users
python manage.py makemigrations customers
python manage.py migrate