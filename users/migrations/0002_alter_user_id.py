# Generated by Django 4.0.3 on 2022-04-22 05:27

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='id',
            field=models.UUIDField(default=uuid.UUID('6ce50588-841e-49ba-838c-e404f472c990'), editable=False, primary_key=True, serialize=False),
        ),
    ]