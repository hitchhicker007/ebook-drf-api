from django.db import models
import uuid


class Courses(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    course = models.CharField(max_length=50)

    class Meta:
        db_table = "courses"
