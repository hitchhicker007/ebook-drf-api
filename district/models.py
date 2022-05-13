from django.db import models
import uuid


# Create your models here.
class Districts(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    district = models.CharField(max_length=50)

    class Meta:
        db_table = "districts"
