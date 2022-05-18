from django.urls import path, re_path
from .views import *

urlpatterns = [
    path('add-book', AddBookView.as_view()),
    path('get-books', GetBooksView.as_view()),
    path('book-details', BookDetailsView.as_view()),

    path('create-buy-request', CreateBuyRequestView.as_view()),
    path('buy-requests', BuyRequestsView.as_view())

]
