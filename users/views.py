import jwt

from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView, ListAPIView, GenericAPIView, RetrieveDestroyAPIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes

from .serializers import *
from .models import *
from .utils import Util

from district.models import Districts


class UserRegistrationView(CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        status_code = status.HTTP_201_CREATED

        user_email = request.data.get('email')
        user = User.objects.get(email=user_email)
        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request)
        relative_link = reverse('verify-email')
        abs_url = 'http://' + str(current_site) + str(relative_link) + "?token=" + str(token)

        email_body = 'Hi there, Please verify your bookstore email using below link!\n' + abs_url + '\nThank you.'

        data = {
            'email_subject': 'Verify your email',
            'email_body': email_body,
            'to_email': user_email
        }

        Util.send_email(data)

        response = {
            'success': True,
            'status code': status_code,
            'message': 'User registered  successfully',
        }

        return Response(response, status=status_code)


class VerifyEmail(GenericAPIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({'email': 'successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as e:
            return Response({'error': 'Activation token expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as e:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


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
                'data': {
                    'name': user_profile.name,
                    'user_id': request.user.id,
                    'profile_id': user_profile.id,
                    'email': request.user.email,
                    'is_verified': request.user.is_verified,
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









class LogoutAPIView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)



class ReqeustPasswordResetEmail(GenericAPIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        email = request.data.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)

            current_site = get_current_site(request)
            relative_link = reverse('password-reset-confirm', kwargs={'uidb64':uidb64,'token':token})
            abs_url = 'http://' + str(current_site) + str(relative_link)

            email_body = 'Hi there, Please use below link to reset your password!\n' + abs_url + '\nThank you.'

            data = {
                'email_subject': 'Password reset email',
                'email_body': email_body,
                'to_email': user.email
            }

            Util.send_email(data)
            return Response({'msg': 'password reset email sent successfully'}, status=status.HTTP_200_OK)
        return Response({'error': 'no user exists with this email!'}, status=status.HTTP_400_BAD_REQUEST)


class PasswordTokenCheckAPI(GenericAPIView):
    permission_classes = (AllowAny,)

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, request for new one.'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success': True, 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as e:
            return Response({'error': 'Token is not valid, request for new one.'}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset successfully'}, status=status.HTTP_200_OK)


