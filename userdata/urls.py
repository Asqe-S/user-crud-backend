from django.urls import path
from userdata.views import *

urlpatterns = [
    path('', UserProfileView.as_view(), name='userdata'),
]


