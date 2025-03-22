
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import UserProfile
import re

User = get_user_model()

class UserProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    phone_number = serializers.CharField(source='user.phone_number', required=False)
    username = serializers.CharField(source='user.username', required=False)
    email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = UserProfile
        fields = ['username', 'profile_picture', 'first_name', 'last_name', 'phone_number', 'email']

    def validate_phone_number(self, value):
        if value and not re.match(r'^[0-9]{10}$', value):
            raise serializers.ValidationError("Phone number must be 10 digits")
        return value

    def update(self, instance, validated_data):
        user_data = validated_data.get('user', {})
        user = instance.user
        
        if 'first_name' in user_data:
            user.first_name = user_data['first_name']
        if 'last_name' in user_data:
            user.last_name = user_data['last_name']
        if 'phone_number' in user_data:
            user.phone_number = user_data['phone_number']
        if 'username' in user_data:
            user.username = user_data['username']
            
        user.save()
    
        if 'profile_picture' in validated_data:
            instance.profile_picture = validated_data['profile_picture']
            instance.save()
            
        return instance
    
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['profile_picture'] = instance.profile_picture.url if instance.profile_picture else None
        return representation
    
class UserSerializer(serializers.ModelSerializer):
    profile_picture = serializers.ImageField(source='users.profile_picture', read_only=True)

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'username', 'email', 'phone_number', 'password', 'is_active', 'profile_picture')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        print(f"User created: {user.email}")  # Debug
        return user
    
    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.is_admin = validated_data.get('is_admin', instance.is_admin)
        instance.is_staff = validated_data.get('is_staff', instance.is_staff)
        instance.is_active = validated_data.get('is_active', instance.is_active)
        instance.is_superadmin = validated_data.get('is_superadmin', instance.is_superadmin)

        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
        instance.save()
        print("User successfully updated")
        return instance

class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField()
    
    def validate_id_token(self, id_token):
        return id_token

