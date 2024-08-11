from rest_framework import serializers
from .models import User



class GenerateCodeSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=12)



class VerificationSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=12)
    code = serializers.CharField(max_length=6)



class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True) 

    class Meta:
        model = User
        fields = ['id', 'phone', 'first_name', 'last_name', 'password' ]

        read_only_fields = ['id', 'password']  

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = super().create(validated_data)
        if password:
            # Hash the password
            user.set_password(password)  
            user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)
        if password:
            # Hash the password
            user.set_password(password)  
            user.save()
        return user



class LoginUserSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(required=True)
    password = serializers.CharField(required=True) 

    class Meta:
        model = User
        fields = ['id', 'phone', 'password']



class LogoutUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = []
