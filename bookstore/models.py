from django.db import models
import uuid


# Create your models here.
class Book(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=100, blank=False)
    description = models.TextField(blank=True)
    image = models.ImageField(upload_to='book_images/', blank=True)
    course = models.CharField(max_length=50, blank=False)
    branch = models.CharField(max_length=50, blank=False)
    sem = models.CharField(max_length=2, blank=False)
    subject = models.CharField(max_length=50, blank=False)
    publication = models.CharField(max_length=50, blank=True)
    district = models.CharField(max_length=50, blank=False)
    seller = models.CharField(max_length=50, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)


class BuyRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, unique=True, editable=False)
    book_id = models.CharField(max_length=50, blank=False)
    buyer_id = models.CharField(max_length=50, blank=False)
    seller_id = models.CharField(max_length=50, blank=False)
    status = models.CharField(max_length=10, blank=False, default='pending')
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
