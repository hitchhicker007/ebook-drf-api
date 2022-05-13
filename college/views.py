from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.response import Response

from .models import Colleges
from .serializers import CollegeSerializer


class GetCollegesView(generics.ListAPIView):
    serializer_class = CollegeSerializer
    permission_classes = (AllowAny,)
    queryset = Colleges.objects.all()


class CollegeView(generics.RetrieveDestroyAPIView):
    permission_classes = (AllowAny,)
    serializer_class = CollegeSerializer

    def get(self, request):
        try:
            college = Colleges.objects.get(id=request.data.get('id'))
            status_code = status.HTTP_200_OK
            response = {
                'college': college.college,
            }
        except:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'message': 'college not found'
            }
        return Response(response, status=status_code)

    def delete(self, request):
        try:
            college = Colleges.objects.get(id=request.data.get('id'))
            college.delete()
            status_code = status.HTTP_200_OK
            response = {
                'success': True,
            }
        except:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'message': 'college not found'
            }
        return Response(response, status=status_code)

    def post(self, request):
        try:
            data = Colleges.objects.get(college=request.data.get('college'))
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'status code': status_code,
                'message': 'College already exists',
            }
        except:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            status_code = status.HTTP_201_CREATED

            response = {
                'success': True,
                'status code': status_code,
                'message': 'College created successfully',
            }

        return Response(response, status=status_code)
