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
            user.delete()
            return Response({"messages": 'Failed to send email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        ActivationLink.objects.create(
            user=user,  token=token, otp=otp, valid_until=valid_until)

        return Response({"message": 'Your account has been successfully created. Please check your email to verify your account.'}, status=status.HTTP_201_CREATED)


class OtpVerifyView(APIView):
    # also use this get method to check the link is valid or not
    def get(self, request, uid, token):

        try:
            pk = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=pk)
            verify_otp = ActivationLink.objects.filter(user=user).first()
            if token == verify_otp.token:
                return Response({'message': 'Good to go.'}, status=status.HTTP_200_OK)
            else:
                raise Exception
        except Exception:
            return Response({'message': 'invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, uid, token):

        try:
            pk = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=pk)
            verify_otp = ActivationLink.objects.filter(user=user).first()
            if token != verify_otp.token:
                raise Exception
        except Exception:
            return Response({'message': 'invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_verified:
            return Response({'message': 'User was already verified'}, status=status.HTTP_200_OK)

        serializer = UserOtpVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data['otp']

        if not verify_otp.valid_until >= timezone.now():
            return Response({"messages": 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

        if verify_otp.otp == otp:
            user.is_verified = True
            user.save()
            verify_otp.delete()
            return Response({'message': 'User successfully verified'}, status=status.HTTP_200_OK)
        else:
            return Response({"messages": 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)


class ResendOtpView(APIView):
    def get(self, request, uid, token):

        try:
            pk = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=pk)
            verify_otp = ActivationLink.objects.filter(user=user).first()
            if token != verify_otp.token:
                raise Exception
        except Exception:
            return Response({'message': 'invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_verified:
            return Response({'message': 'User was already verified'}, status=status.HTTP_200_OK)
        otp = get_random_string(length=6, allowed_chars='9876543210')

        valid_until = timezone.now() + timedelta(minutes=10)

        try:
            subject = 'Account verification mail'
            send_verification_email(
                subject, uid, token, valid_until,  user.username, user.email, otp)
        except Exception:
            return Response({"messages": 'Failed to resend OTP. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        verify_otp.otp = otp
        verify_otp.valid_until = valid_until
        verify_otp.save()
        return Response({"messages": 'OTP successfully resent. Please check your email.'}, status=status.HTTP_200_OK)


class ForgotPasswordemailView(APIView):
    def post(self, request):
        serializer = UsernameSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        try:
            user = None
            if '@' in username:
                user = User.objects.get(email=username)
            else:
                user = User.objects.get(username=username)

        except:
            return Response({'message': 'user not found'}, status=status.HTTP_404_NOT_FOUND)

        valid_until = timezone.now() + timedelta(minutes=10)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        try:
            subject = 'Password reset mail'
            send_verification_email(
                subject, uid, token, valid_until,  user.username, user.email)
        except Exception:
            return Response({"messages": 'Failed to send email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        reset_link = ActivationLink.objects.filter(user=user).first()
        if reset_link:
            reset_link.token = token
            reset_link.valid_until = valid_until
            reset_link.save()
        else:
            ActivationLink.objects.create(
                user=user,  token=token, valid_until=valid_until)

        return Response(status=status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    def post(self, request, uid, token):

        try:
            pk = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=pk)
            verify_link = ActivationLink.objects.filter(user=user).first()
            if token != verify_link.token:
                raise Exception
        except Exception:
            return Response({'message': 'invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)

        if not verify_link.valid_until >= timezone.now():
            return Response({"messages": 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']

        user.set_password(password)
        user.save()
        verify_link.delete()
        return Response(status=status.HTTP_200_OK)
