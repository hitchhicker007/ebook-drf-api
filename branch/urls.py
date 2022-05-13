from django.urls import path
from .views import *

urlpatterns = [
    path('get-branches', GetBranchesView.as_view()),
    path('branch', BranchView.as_view())
]
