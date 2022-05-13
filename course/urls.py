from django.urls import path
from .views import *

urlpatterns = [
    path('get-courses', GetCoursesView.as_view()),
    path('course', CourseView.as_view()),
]
