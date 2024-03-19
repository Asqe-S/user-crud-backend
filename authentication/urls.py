from django.urls import path
from authentication.views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),

]
