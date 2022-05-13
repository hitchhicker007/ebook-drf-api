from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.response import Response

from .models import Courses
from .serializers import CourseSerializer


class GetCoursesView(generics.ListAPIView):
    serializer_class = CourseSerializer
    permission_classes = (AllowAny,)
    queryset = Courses.objects.all()


class CourseView(generics.RetrieveDestroyAPIView):
    permission_classes = (AllowAny,)
    serializer_class = CourseSerializer

    def get(self, request):
        try:
            course = Courses.objects.get(id=request.data.get('id'))
            status_code = status.HTTP_200_OK
            response = {
                'course': course.course,
            }
        except:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'message': 'course not found'
            }
        return Response(response, status=status_code)

    def delete(self, request):
        try:
            course = Courses.objects.get(id=request.data.get('id'))
            course.delete()
            status_code = status.HTTP_200_OK
            response = {
                'success': True,
            }
        except:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'message': 'course not found'
            }
        return Response(response, status=status_code)

    def post(self, request):
        try:
            data = Courses.objects.get(course=request.data.get('course'))
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'status code': status_code,
                'message': 'Course already exists',
            }
        except:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            status_code = status.HTTP_201_CREATED

            response = {
                'success': True,
                'status code': status_code,
                'message': 'Course created successfully',
            }

        return Response(response, status=status_code)
