from users.serializers import Base64ImageField

from rest_framework import serializers
from .models import *


class BookSerializer(serializers.ModelSerializer):
    image = Base64ImageField(
        max_length=None, use_url=True
    )

    class Meta:
        model = Book
        fields = '__all__'
