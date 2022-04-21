from django.shortcuts import render
from .models import *
from .serializers import *

from rest_framework.generics import CreateAPIView, ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication


# Create your views here.

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


class GetUserBooksView(ListAPIView):
    serializer_class = BookSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)

    def get_queryset(self):
        user = self.request.user
        return Book.objects.filter(seller=user.id)
