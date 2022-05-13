from django.db import models
import uuid
# Create your models here.


class Colleges(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False,unique=True)
    college = models.CharField(max_length=50)

    class Meta:
        db_table = "colleges"
