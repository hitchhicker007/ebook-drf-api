from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView, ListAPIView, GenericAPIView
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
                'data': [{
                    'name': user_profile.name,
                    'email': request.user.email,
                    'district': district.district,
                    'course': course.course,
                    'branch': branch.branch,
                    'sem': user_profile.sem,
                    'college': college.college,
                    'avatar': serializer.data['avatar']
                }]
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
            name = request.data.get('name')
            district = request.data.get('district')
            course = request.data.get('course')
            branch = request.data.get('branch')
            sem = request.data.get('sem')
            college = request.data.get('college')

            if name != None and name != "":
                instance.name = name
            if district != None and district != "":
                instance.district = district
            if course != None and course != "":
                instance.course = course
            if branch != None and branch != "":
                instance.branch = branch
            if sem != None and sem != "":
                instance.sem = sem
            if college != None and college != "":
                instance.college = college

            instance.save()
            status_code = status.HTTP_200_OK


            district = Districts.objects.get(id=instance.district)
            course = Courses.objects.get(id=instance.course)
            branch = Branches.objects.get(id=instance.branch)
            college = Colleges.objects.get(id=instance.college)

            response = {
                'success': 'true',
                'status code': status_code,
                'message': 'User profile updated successfully',
                'data': [{
                    'name': instance.name,
                    'email': request.user.email,
                    'district': district.district,
                    'course': course.course,
                    'branch': branch.branch,
                    'sem': instance.sem,
                    'college': college.college,
                }]
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


class ImageList(ListAPIView):
    'List all images'

    serializer_class = ImageSerializer
    permission_classes = (IsAuthenticated,)
    queryset = Image.objects.all()
    authentication_classes = (JWTAuthentication,)


class ImageDetail(RetrieveAPIView):
    """Retrieve an image instance"""

    serializer_class = ImageSerializer
    permission_classes = (IsAuthenticated,)
    queryset = Image.objects.all()
    authentication_classes = (JWTAuthentication,)


class ImageCreate(CreateAPIView):
    """Create a new image instance"""

    serializer_class = ImageSerializer

    def post(self, request):
        serializer = ImageSerializer(data=request.data)
        if serializer.is_valid():
            # Save request image in the database
            serializer.save()

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
