from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.conf import settings
from django.http import JsonResponse
import requests
from django.contrib.auth.models import User


class UserDetailView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        user=request.user
        return Response({
            'username':user.username,
            'email': user.email,
            'date_joined': user.date_joined.strftime('%Y-%m-%d %H:%M:%S'),
            'message': f'Hello, {user.username}! Welcome back!'
        })

class SignupView(APIView):


    def post(self,request):
        
        username=request.data.get('username')
        email=request.data.get('email')
        password=request.data.get('password')

        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already taken"}, status=status.HTTP_400_BAD_REQUEST)
        
        new_user=User.objects.create_user(username=username, password=password, email=email)
        new_user.save()
        return Response({'message':"User created successfully"},status=status.HTTP_201_CREATED)

class WelcomeView(APIView):
    def get(self, request):
        return Response({'message': 'Hello! How are you doing'}, status=status.HTTP_200_OK)
    
def google_login(request):
    google_client_id = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
    redirect_uri = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI
    scope = "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
    auth_url = f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={google_client_id}&redirect_uri={redirect_uri}&scope={scope}&access_type=offline"
    return redirect(auth_url)

def google_auth_callback(request):
    code = request.GET.get('code')
    if not code:
        return JsonResponse({'error': 'No code provided'}, status=400)

    # Exchange code for tokens
    token_url = 'https://oauth2.googleapis.com/token'
    payload = {
        'code': code,
        'client_id': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
        'client_secret': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
        'redirect_uri': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    token_response = requests.post(token_url, data=payload).json()

    # Get user info from Google
    user_info_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    headers = {'Authorization': f"Bearer {token_response.get('access_token')}"}
    user_info_response = requests.get(user_info_url, headers=headers).json()

    if 'email' not in user_info_response:
        return JsonResponse({'error': 'Failed to fetch user info'}, status=400)

    # Get or create user in Django
    email = user_info_response['email']
    username = user_info_response.get('name', email.split('@')[0])

    user, created = User.objects.get_or_create(email=email, defaults={'username': username})
    if created:
        user.save()

    # Generate JWT tokens for your app
    refresh = RefreshToken.for_user(user)
    return JsonResponse({
        'message': 'Authentication successful',
        'username': user.username,
        'email': user.email,
        'tokens': {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        },
    })