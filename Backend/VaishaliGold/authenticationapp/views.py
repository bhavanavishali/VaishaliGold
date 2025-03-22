from django.shortcuts import render
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.cache import cache
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import *
from .models import UserProfile
from django.utils import timezone
from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
import logging
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework_simplejwt.views import TokenObtainPairView
from django.shortcuts import get_object_or_404

from django.http import JsonResponse

from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie

logger = logging.getLogger(__name__)

from django.core.mail import send_mail
from datetime import timedelta
import random

User = get_user_model()


# Create your views here.
class SignupView(APIView):
    permission_classes = [AllowAny]
    authentication_classes=[]

    def post(self, request):
        print(request.data)

        logger.info(f"Received signup request: {request.data}")
        serializer = UserSerializer(data=request.data)
        print("Request data:", request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            UserProfile.objects.create(user=user)
            # refresh = RefreshToken.for_user(user)
            return Response({
                'user': UserSerializer(user).data
                # 'token': str(refresh.access_token)
            }, status=status.HTTP_201_CREATED)
        logger.error(f"Validation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(ensure_csrf_cookie, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        

        if not email or not password:
            return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.is_active:
            return Response({'error': 'Account not verified or blocked.'}, status=status.HTTP_403_FORBIDDEN)

        # Generate token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        response = Response({
            'user': {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'username': user.username,
                'email': user.email,
            },
            'message': 'Login successful'
        }, status=status.HTTP_200_OK)

        # Set the token in HttpOnly cookie
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,  # Prevent JavaScript access
            secure=False,  # Use secure cookies (HTTPS)
            samesite='Lax',  # Adjust as needed ('Strict' for CSRF protection)
            max_age=60 * 60,  # 1 hour in seconds (matching your JWT settings)
            path='/'  # Available across the whole domain
        )
        
        # Set the refresh token in HttpOnly cookie
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,  # Prevent JavaScript access
            secure=False,  # Use secure cookies (HTTPS)
            samesite='Lax',  # Adjust as needed ('Strict' for CSRF protection)
            max_age=7 * 24 * 60 * 60,  # 7 days in seconds (matching your JWT settings)
            path='/'  # Available across the whole domain
        )
        return response
from django.views.decorators.csrf import csrf_exempt

# @method_decorator(csrf_exempt, name='dispatch')
class LogoutView(APIView):
    permission_classes=[]
    @csrf_exempt
    def post(self, request):
        response = Response({
            'type': 'SUCCESS',
            'message': 'Logout successful'
        }, status=status.HTTP_200_OK)
        
        # Clear the access and refresh tokens
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
      
        
        return response
    