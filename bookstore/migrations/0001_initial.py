# Generated by Django 4.0.3 on 2022-05-13 13:15

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Book',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True)),
                ('image', models.ImageField(blank=True, upload_to='book_images/')),
                ('course', models.CharField(max_length=50)),
                ('branch', models.CharField(max_length=50)),
                ('sem', models.CharField(max_length=2)),
                ('subject', models.CharField(max_length=50)),
                ('publication', models.CharField(blank=True, max_length=50)),
                ('district', models.CharField(max_length=50)),
                ('seller', models.CharField(max_length=50)),
            ],
        ),
    ]