from rest_framework import serializers
from authentication.models import User
import re


username_regex = r'^(?=.*[a-zA-Z])[a-zA-Z0-9_.-]{4,30}$'
email_regx = r'^[a-zA-Z0-9._]{2,30}@[a-zA-Z0-9.-]{2,30}\.[a-zA-Z]{2,30}$'
password_regx = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z0-9!@#$%^&*()_+=\-[\]{}|\\:;"\'<>,.?/~]{8,30}$'


class UserRegistrationSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField()

    class Meta:
        model = User
        fields = ('username',  'email', 'password',
                  'confirm_password')
        extra_kwargs = {'password': {'write_only': True},
                        'confirm_password': {'write_only': True}}

    def validate_username(self, value):
        if re.match(username_regex, value):
            return value
        else:
            raise serializers.ValidationError(
                'Username must be 4-30 characters long and can contain only alphanumeric values.'
            )

    def validate_email(self, value):
        if re.match(email_regx, value):
            return value
        else:
            raise serializers.ValidationError(
                'Enter a valid email address.'
            )

    def validate_password(self, value):
        if re.match(password_regx, value):
            return value
        else:
            raise serializers.ValidationError(
                'Enter a valid password.'
            )

    def validate_confirm_password(self, value):
        password = self.initial_data.get('password')
        if value == password:
            return value
        else:
            raise serializers.ValidationError(
                'Password mismatch.'
            )


class UserOtpVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField()


class UsernameSerializer(serializers.Serializer):
    username = serializers.CharField()


class ForgotPasswordSerializer(serializers.Serializer):
    password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate_password(self, value):
        if re.match(password_regx, value):
            return value
        else:
            raise serializers.ValidationError(
                'Enter a valid password.'
            )

    def validate_confirm_password(self, value):
        password = self.initial_data.get('password')
        if value == password:
            return value
        else:
            raise serializers.ValidationError(
                'Password mismatch.'
            )


class UserLoginViewSerializer(UsernameSerializer):
    password = serializers.CharField(write_only=True)
