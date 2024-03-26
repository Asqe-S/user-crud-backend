from rest_framework import serializers
from authentication.models import User
# from django.utils.text import slugify
import re

from authentication.serializers import password_regx
from django.contrib.auth.hashers import make_password


class UserDataSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'profile_picture',
                  'password', 'confirm_password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, value):
        if not re.match(password_regx, value):
            raise serializers.ValidationError('Enter a valid password.')
        return value

    def validate(self, data):
        if 'password' in data:
            if 'confirm_password' not in data:
                raise serializers.ValidationError(
                    {"confirm_password": "Confirm password is required."})
            if data['password'] != data['confirm_password']:
                raise serializers.ValidationError(
                    {"confirm_password": "Passwords do not match."})
        return data

    def update(self, instance, validated_data):
        new_profile_picture = validated_data.get('profile_picture')
        password = validated_data.get('password')

        if new_profile_picture:
            if instance.profile_picture:
                instance.profile_picture.delete()

            # file_extension = new_profile_picture.name.split('.')[-1]
            # new_profile_picture.name = f"{slugify(instance.username)}.{
            #     file_extension}"
        if password:
            validated_data['password'] = make_password(password)
        return super().update(instance, validated_data)
