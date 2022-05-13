from rest_framework import serializers
from .models import Colleges


class CollegeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Colleges
        fields = ('id', 'college')
