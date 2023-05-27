
from django.urls import path
from account import views
from account.views import userPasswordResetView

urlpatterns = [
    path('register/',views.userRegistrationView.as_view(), name='register'),
    path('login/',views.userLoginView.as_view(),name='login'),
    path('profile/',views.userProfileView.as_view(),name='profile'),
    path('changepassword/',views.userChangePasswordView.as_view(),name='changepassword'),
    path('send-reset-password-email/',views.sendPasswordResetEmailView.as_view(),name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', userPasswordResetView.as_view(), name='reset-password'),

]
