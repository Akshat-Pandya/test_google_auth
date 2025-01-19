from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from authapp.views import SignupView,UserDetailView,WelcomeView
from .views import google_login, google_auth_callback
urlpatterns=[
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/user/', UserDetailView.as_view(), name='user_details'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('api/', WelcomeView.as_view(), name='welcome_message'),
    path('auth/google/', google_login, name='google_login'),
    path('auth/google/callback/', google_auth_callback, name='google_callback'),
    
]