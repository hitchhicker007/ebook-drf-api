from django.urls import path
from .views import *

urlpatterns = [
    path('signup', UserRegistrationView.as_view()),
    path('login', UserLoginView.as_view()),
    path('profile', UserProfileView.as_view()),
    path('logout', LogoutAPIView.as_view(), name='logout'),
    path('update-profile', UpdateProfileView.as_view()),

    path('verify-email', verifyEmail, name='verify-email'),
    path('request-reset-email', ReqeustPasswordResetEmail.as_view(), name='request-reset-email'),
    # path('password-reset/<uidb64>/<token>', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset/<uidb64>/<token>', passwordResetView, name='password-reset-confirm'),
    # path('password-reset-complete', SetNewPasswordView.as_view(), name='password-reset-complete'),
    path('send-email-confirmation', SendEmailConfirmationView.as_view()),

]
