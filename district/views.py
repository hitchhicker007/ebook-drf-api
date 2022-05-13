from django.shortcuts import render

from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.response import Response

from .models import Districts
from .serializers import DistrictSerializer


# Create your views here.
class DistrictView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = DistrictSerializer

    def get(self, request):
        try:
            district = Districts.objects.get(id=request.data.get('id'))
            status_code = status.HTTP_200_OK
            response = {
                'district': district.district,
            }
        except Exception as e:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'exception': str(e),
                'message': 'district not found'
            }
        return Response(response, status=status_code)

    def delete(self, request):
        try:
            district = Districts.objects.get(id=request.data.get('id'))
            district.delete()
            status_code = status.HTTP_200_OK
            response = {
                'success': True,
            }
        except Exception as e:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'exception': str(e),
                'message': 'district not found'
            }
        return Response(response, status=status_code)

    def post(self, request):
        try:
            data = Districts.objects.get(district=request.data.get('district'))
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'status code': status_code,
                'message': 'District already exists',
            }
        except Exception as e:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            status_code = status.HTTP_201_CREATED

            response = {
                'success': True,
                'status code': status_code,
                'message': 'District created successfully',
            }

        return Response(response, status=status_code)


class GetDistrictsView(generics.ListAPIView):
    serializer_class = DistrictSerializer
    permission_classes = (AllowAny,)
    queryset = Districts.objects.all()
