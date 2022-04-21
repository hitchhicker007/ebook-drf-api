from django.urls import path,re_path
from .views import *

urlpatterns = [
    path('signup', UserRegistrationView.as_view()),
    path('login', UserLoginView.as_view()),
    path('profile', UserProfileView.as_view()),
    path('logout', LogoutAPIView.as_view(), name='logout'),
    path('create-district', CreateDistrictView.as_view()),
    path('create-college', CreateCollegeView.as_view()),
    path('create-branch', CreateBranchView.as_view()),
    path('create-course', CreateCourseView.as_view()),
    path('get-courses', GetCoursesView.as_view()),
    path('get-colleges', GetCollegesView.as_view()),
    path('get-districts', GetDistrictsView.as_view()),
    path('get-branches', GetBranchesView.as_view()),
    path('update-profile', UpdateProfileView.as_view()),

    re_path(r'^images/$', ImageList.as_view()),
    re_path(r'^images/(?P<pk>[0-9]+)/$', ImageDetail.as_view()),
    re_path(r'^images/create/$', ImageCreate.as_view()),
]
