from django.urls import path
from authentication.views import *

urlpatterns = [
    path('register/<str:role>/', UserRegistrationView.as_view(), name='register'),
    path('verify-otp/<str:uid>/<str:token>/',
         OtpVerifyView.as_view(), name='verify_otp'),
    path('resend-otp/<str:uid>/<str:token>/',
         ResendOtpView.as_view(), name='verify_otp'),
    path('forgot-password-user/',
         ForgotPasswordemailView.as_view(), name='reset_password_user'),
    path('forgot-password/<str:uid>/<str:token>/',
         ForgotPasswordView.as_view(), name='reset_password'),

    path('login/<str:role>/', CustomLoginView.as_view(), name='custom_login'),
]
