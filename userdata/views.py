from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework import permissions
from django.core.files.storage import default_storage

from userdata.serializers import *


class UserAuth(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and not request.user.is_blocked


class UserProfileView(APIView):
    permission_classes = [UserAuth]

    def get(self, request):
        serializer = UserDataSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        serializer = UserDataSerializer(
            request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response( serializer.data,  status=status.HTTP_200_OK)
    
    def delete(self, request):
        user = request.user
        if user.profile_picture:
            default_storage.delete(user.profile_picture.path)
        # user.delete()
        return Response({"message": "User deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
