from django.urls import path
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

    path('district', DistrictView.as_view()),
    path('college', CollegeView.as_view()),
    path('course', CourseView.as_view()),
    path('branch', BranchView.as_view())
]
