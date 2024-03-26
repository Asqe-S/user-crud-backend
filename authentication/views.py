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
from authentication.serializers import *

# Create your views here.


class UserRegistrationView(APIView):
    def post(self, request, role):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.validated_data.pop('confirm_password', None)

        user = User.objects.create_user(**serializer.validated_data)

        if role == 'merchant':
            user.is_merchant = True

        user.save()

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
            return Response({"message": 'Failed to send email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        ActivationLink.objects.create(
            user=user,  token=token, otp=otp, valid_until=valid_until)

        return Response({"message": 'Your account has been successfully created. Please check your email to verify your account.'}, status=status.HTTP_201_CREATED)


class OtpVerifyView(APIView):
    def get(self, request, uid, token):

        try:
            pk = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=pk)
            try:
                verify_otp = ActivationLink.objects.get(user=user)
            except ActivationLink.DoesNotExist:
                raise Exception("Invalid activation link")
            if verify_otp.otp is None:
                raise Exception('its a password reset link')
            if token != verify_otp.token:
                raise Exception('invalid activation link')
            else:
                return Response({'message': 'Good to go.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

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
            return Response({"message": 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

        if verify_otp.otp == otp:
            user.is_verified = True
            user.save()
            verify_otp.delete()
            pos = 'merchant' if user.is_merchant else 'user'
            return Response({'message': 'User successfully verified', 'role': pos}, status=status.HTTP_200_OK)
        else:
            return Response({"message": 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)


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
            return Response({"message": 'Failed to resend OTP. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        verify_otp.otp = otp
        verify_otp.valid_until = valid_until
        verify_otp.save()
        return Response({"message": 'OTP successfully resent. Please check your email.'}, status=status.HTTP_200_OK)


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
            return Response({"message": 'Failed to send email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        reset_link = ActivationLink.objects.filter(user=user).first()
        if reset_link:
            reset_link.token = token
            reset_link.valid_until = valid_until
            reset_link.save()
        else:
            ActivationLink.objects.create(
                user=user,  token=token, valid_until=valid_until)
        pos = 'merchant' if user.is_merchant else (
            'superuser' if user.is_superuser else 'user')
        return Response({'pos': pos}, status=status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    def get(self, request, uid, token):

        try:
            pk = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=pk)
            try:
                verify_otp = ActivationLink.objects.get(user=user)
            except ActivationLink.DoesNotExist:
                raise Exception("Invalid link")

            if token != verify_otp.token:
                raise Exception("Invalid link")
            if verify_otp.otp :
                raise Exception('its a account activation link')
            if not verify_otp.valid_until >= timezone.now():
                raise Exception("Link expired")
            else:

                return Response({'message': 'Good to go.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

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
            return Response({"message": 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']

        user.set_password(password)
        user.save()
        verify_link.delete()
        pos = 'merchant' if user.is_merchant else (
            'superuser' if user.is_superuser else 'user')
        return Response({'pos': pos}, status=status.HTTP_200_OK)


class CustomLoginView(APIView):
    def post(self, request, role):
        serializer = UserLoginViewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        if '@' in username:
            temp_user = User.objects.filter(email=username).first()
            if not temp_user:
                return Response({"message": 'Invalid user credentials'}, status=status.HTTP_404_NOT_FOUND)
            username = temp_user.username

        user = authenticate(username=username, password=password)

        if user is not None:
            data = {}
            pos = 'merchant' if user.is_merchant else (
                'superuser' if user.is_superuser else 'user')
            if role != pos:
                data['pos'] = False

            elif not user.is_verified:
                otp = get_random_string(length=6, allowed_chars='9876543210')
                valid_until = timezone.now() + timedelta(minutes=10)

                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)

                try:
                    subject = 'New Account verification mail'
                    send_verification_email(
                        subject, uid, token, valid_until,  user.username, user.email, otp)
                except Exception:
                    return Response({"message": 'Failed to send verification email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                user_otp = ActivationLink.objects.filter(user=user).first()
                if user_otp:
                    user_otp.token = token
                    user_otp.otp = otp
                    user_otp.valid_until = valid_until
                    user_otp.save()
                else:
                    ActivationLink.objects.create(
                        user=user, token=token, otp=otp, valid_until=valid_until)

                data['notverified'] = True

            elif user.is_blocked:
                data['is_blocked'] = True

            else:

                login(request, user)
                refresh = RefreshToken.for_user(user)

                refresh['role'] = role
                refresh['user'] = user.username
                refresh['is_blocked'] = False

                data['role'] = role
                data['refresh'] = str(refresh)
                data['access'] = str(refresh.access_token)

            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"message": 'Invalid user credentials'}, status=status.HTTP_404_NOT_FOUND)
