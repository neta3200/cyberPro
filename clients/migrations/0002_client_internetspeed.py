# Generated by Django 4.2 on 2023-05-25 13:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('clients', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='client',
            name='internetSpeed',
            field=models.IntegerField(default=1, max_length=10),
            preserve_default=False,
        ),
    ]
