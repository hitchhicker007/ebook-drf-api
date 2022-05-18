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


class BookListingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Book
        fields = ('id', 'image', 'name', 'subject', 'publication')


class BuyRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = BuyRequest
        fields = '__all__'
