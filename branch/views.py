from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.response import Response

from .models import Branches
from .serializers import BranchSerializer


class GetBranchesView(generics.ListAPIView):
    serializer_class = BranchSerializer
    permission_classes = (AllowAny,)
    queryset = Branches.objects.all()


class BranchView(generics.RetrieveDestroyAPIView):
    permission_classes = (AllowAny,)
    serializer_class = BranchSerializer

    def get(self, request):
        try:
            branch = Branches.objects.get(id=request.data.get('id'))
            status_code = status.HTTP_200_OK
            response = {
                'branch': branch.branch,
            }
        except:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'message': 'branch not found'
            }
        return Response(response, status=status_code)

    def delete(self, request):
        try:
            branch = Branches.objects.get(id=request.data.get('id'))
            branch.delete()
            status_code = status.HTTP_200_OK
            response = {
                'success': True,
            }
        except:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'message': 'branch not found'
            }
        return Response(response, status=status_code)

    def post(self, request):
        try:
            data = Branches.objects.get(branch=request.data.get('branch'))
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'status code': status_code,
                'message': 'Branch already exists',
            }
        except:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            status_code = status.HTTP_201_CREATED

            response = {
                'success': True,
                'status code': status_code,
                'message': 'Branch created successfully',
            }

        return Response(response, status=status_code)