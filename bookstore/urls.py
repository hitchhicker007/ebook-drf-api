from django.urls import path, re_path
from .views import *

urlpatterns = [
    path('add-book', AddBookView.as_view()),

    path('get-books', GetBooksView.as_view())


]
