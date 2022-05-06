from .serializers import *

from rest_framework.generics import CreateAPIView, ListAPIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend

from rest_framework.filters import SearchFilter


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
    serializer_class = BookListingSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter]
    filterset_fields = ['seller', 'name', 'subject', 'course', 'branch', 'sem', 'district']
    search_fields = ['name', 'subject']


