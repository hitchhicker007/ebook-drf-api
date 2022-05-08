from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView, ListAPIView, GenericAPIView, RetrieveDestroyAPIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from .serializers import *
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import *
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser


class UserRegistrationView(CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        status_code = status.HTTP_201_CREATED

        response = {
            'success': True,
            'status code': status_code,
            'message': 'User registered  successfully',
        }

        return Response(response, status=status_code)


class UserLoginView(RetrieveAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = (AllowAny,)
    queryset = ""

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        response = {
            'success': 'True',
            'status code': status.HTTP_200_OK,
            'message': 'User logged in successfully',
            'token': serializer.data['token'],
        }
        status_code = status.HTTP_200_OK

        return Response(response, status=status_code)


class UserProfileView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)

    def get(self, request):
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            serializer = GetProfileSerializer(user_profile)
            district = Districts.objects.get(id=user_profile.district)
            course = Courses.objects.get(id=user_profile.course)
            branch = Branches.objects.get(id=user_profile.branch)
            college = Colleges.objects.get(id=user_profile.college)
            status_code = status.HTTP_200_OK
            response = {
                'success': 'true',
                'status code': status_code,
                'message': 'User profile fetched successfully',
                # 'data': serializer.data
                'data': {
                    'name': user_profile.name,
                    'user_id': request.user.id,
                    'profile_id': user_profile.id,
                    'email': request.user.email,
                    'district': {
                        'id': district.id,
                        'district': district.district
                    },
                    'college': {
                        'id': college.id,
                        'college': college.college
                    },
                    'course': {
                        'id': course.id,
                        'course': course.course
                    },
                    'branch': {
                        'id': branch.id,
                        'branch': branch.branch
                    },
                    'sem': user_profile.sem,
                    'avatar': serializer.data['avatar']
                }
            }
        except Exception as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'success': 'false',
                'status code': status.HTTP_400_BAD_REQUEST,
                'message': 'User does not exists',
                'error': str(e)
            }
        return Response(response, status=status_code)


class UpdateProfileView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)

    def post(self, request):
        try:
            instance = UserProfile.objects.get(user=request.user)

            serializer = UpdateProfileSerializer(instance, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            status_code = status.HTTP_200_OK
            response = serializer.data

        except Exception as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'success': 'false',
                'status code': status.HTTP_400_BAD_REQUEST,
                'message': 'User does not exists',
                'error': str(e)
            }
        return Response(response, status=status_code)


class BlacklistTokenView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    authentication_classes = (JWTAuthentication,)

    def post(self, request):
        try:
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class CreateDistrictView(CreateAPIView):
    serializer_class = DistrictSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        try:
            data = Districts.objects.get(district=request.data.get('district'))
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'status code': status_code,
                'message': 'District already exists',
            }
        except:
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


class CreateBranchView(CreateAPIView):
    serializer_class = BranchSerializer
    permission_classes = (AllowAny,)

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


class CreateCourseView(CreateAPIView):
    serializer_class = CourseSerializer
    permission_classes = (AllowAny,)

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


class CreateCollegeView(CreateAPIView):
    serializer_class = CollegeSerializer
    permission_classes = (AllowAny,)

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


class GetCoursesView(ListAPIView):
    serializer_class = CourseSerializer
    permission_classes = (AllowAny,)
    queryset = Courses.objects.all()


class GetDistrictsView(ListAPIView):
    serializer_class = DistrictSerializer
    permission_classes = (AllowAny,)
    queryset = Districts.objects.all()


class GetBranchesView(ListAPIView):
    serializer_class = BranchSerializer
    permission_classes = (AllowAny,)
    queryset = Branches.objects.all()


class GetCollegesView(ListAPIView):
    serializer_class = CollegeSerializer
    permission_classes = (AllowAny,)
    queryset = Colleges.objects.all()


class LogoutAPIView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


class DistrictView(RetrieveDestroyAPIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        try:
            district = Districts.objects.get(id=request.data.get('id'))
            status_code = status.HTTP_200_OK
            response = {
                'district': district.district,
            }
        except:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
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
        except:
            status_code = status.HTTP_403_FORBIDDEN
            response = {
                'success': False,
                'message': 'district not found'
            }
        return Response(response, status=status_code)


class CollegeView(RetrieveDestroyAPIView):
    permission_classes = (AllowAny,)

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


class CourseView(RetrieveDestroyAPIView):
    permission_classes = (AllowAny,)

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


class BranchView(RetrieveDestroyAPIView):
    permission_classes = (AllowAny,)

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
