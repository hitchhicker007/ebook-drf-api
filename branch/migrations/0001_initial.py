# Generated by Django 4.0.3 on 2022-05-13 13:15

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Branches',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('branch', models.CharField(max_length=50)),
                ('course', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'branches',
            },
        ),
    ]