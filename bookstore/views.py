from .serializers import *

from rest_framework.generics import CreateAPIView, ListAPIView, RetrieveUpdateDestroyAPIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter
from rest_framework.pagination import LimitOffsetPagination

import os

from course.models import Courses
from branch.models import Branches
from district.models import Districts


class AddBookView(CreateAPIView):
    serializer_class = BookSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            status_code = status.HTTP_201_CREATED

            response = {
                'success': True,
                'status code': status_code,
                'message': 'Book added successfully',
            }
        except Exception as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'success': 'false',
                'status code': status.HTTP_400_BAD_REQUEST,
                'message': 'error while saving book',
                'error': str(e)
            }

        return Response(response, status=status_code)


class GetBooksView(ListAPIView):
    queryset = Book.objects.all()
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)
    serializer_class = BookListingSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter]
    filterset_fields = ['seller', 'name', 'subject', 'course', 'branch', 'sem', 'district']
    search_fields = ['name', 'subject']
    pagination_class = LimitOffsetPagination


class BookDetailsView(RetrieveUpdateDestroyAPIView):
    serializer_class = BookSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)

    def get(self, request):
        try:
            book = Book.objects.get(id=request.data.get('id'))
            serializer = BookSerializer(book)

            course = Courses.objects.get(id=book.course)
            branch = Branches.objects.get(id=book.branch)
            district = Districts.objects.get(id=book.district)
            status_code = status.HTTP_200_OK
            response = {
                'id': book.id,
                'name': book.name,
                'description': book.description,
                'image': serializer.data['image'],
                'course': course.course,
                'branch': branch.branch,
                'sem': book.sem,
                'subject': book.subject,
                'district': district.district,
                'seller': book.seller
            }
        except Exception as e:
            status_code = status.HTTP_204_NO_CONTENT
            response = {
                'error': str(e)
            }
        return Response(response, status=status_code)

    def put(self, request):
        try:
            data = request.data
            qs = Book.objects.get(id=data.get('id'))
            serializer = BookSerializer(qs, data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            status_code = status.HTTP_200_OK
            response = serializer.data
        except Exception as e:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'error': str(e)
            }

        return Response(response, status=status_code)

    def delete(self, request):
        try:
            book = Book.objects.get(id=request.data.get('id'))
            if book.seller == request.user.id:
                return Response({'error': 'you do not have access'}, status=status.HTTP_401_UNAUTHORIZED)
            book.delete()
            try:
               os.remove(book.image.path)
            except Exception as e:
                print("----{}".format(str(e)))
            status_code = status.HTTP_204_NO_CONTENT
            response = {
                'success': True,
            }
        except Exception as e:
            status_code = status.HTTP_404_NOT_FOUND
            response = {
                'success': False,
                'error': str(e)
            }
        return Response(response, status=status_code)
