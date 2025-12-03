from django.contrib.auth.models import User
from rest_framework import serializers

# serializer: convert complex data such as querysets and model instances to native Python datatypes that can then be easily rendered into JSON, XML or other content types.
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user