from rest_framework import serializers
from .models import UserToken

class UserTokenSerializer(serializers.ModelSerializer):
    email = serializers.ReadOnlyField(source='user.email')
    class Meta:
        model = UserToken
        read_only_fields = ('email','access_token','refresh_token')
        fields = ('email','access_token','refresh_token')