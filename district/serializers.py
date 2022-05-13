from rest_framework import serializers
from .models import Districts


class DistrictSerializer(serializers.ModelSerializer):
    class Meta:
        model = Districts
        fields = ('id', 'district')
