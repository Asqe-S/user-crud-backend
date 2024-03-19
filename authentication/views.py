from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from django.utils import timezone
from datetime import timedelta

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from django.utils.crypto import get_random_string
from authentication.email import send_verification_email
from authentication.models import ActivationLink, User

from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError

from authentication.serializers import *

# Create your views here.


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.validated_data.pop('confirm_password', None)

        user = User.objects.create_user(**serializer.validated_data)

        otp = get_random_string(length=6, allowed_chars='9876543210')

        valid_until = timezone.now() + timedelta(minutes=10)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        try:
            subject = 'Account verification mail'
            send_verification_email(
                subject, uid, token, valid_until,  user.username, user.email, otp)
        except Exception as e:
            print(e)
            user.delete()
            return Response({"messages": 'Failed to send email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        ActivationLink.objects.create(
            user=user, uid=uid, token=token, otp=otp, valid_until=valid_until)

        return Response({"message": 'Your account has been successfully created. Please check your email to verify your account.'}, status=status.HTTP_201_CREATED)

