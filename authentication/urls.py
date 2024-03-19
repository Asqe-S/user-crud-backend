from django.urls import path
from authentication.views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('verify-otp/<str:uid>/<str:token>/',
         OtpVerifyView.as_view(), name='verify_otp'),
    path('resend-otp/<str:uid>/<str:token>/',
         ResendOtpView.as_view(), name='verify_otp'),
]
