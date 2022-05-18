from django.db import models
import uuid


class Chat(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    sender = models.CharField(max_length=50, blank=False)
    receiver = models.CharField(max_length=50, blank=False)
    content = models.TextField(blank=False)
