from django.urls import path
from .views import *

urlpatterns = [
    path('get-districts', GetDistrictsView.as_view()),
    path('district', DistrictView.as_view()),
]
