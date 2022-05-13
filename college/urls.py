from django.urls import path
from .views import *

urlpatterns = [
    path('college', CollegeView.as_view()),
    path('get-colleges', GetCollegesView.as_view()),
]
