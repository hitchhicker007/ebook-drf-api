from django.urls import path, re_path
from .views import *

urlpatterns = [
    path('add-book', AddBookView.as_view()),
    path('get-user-books', GetUserBooksView.as_view()),
]
