from django.contrib.auth import authenticate
from django.shortcuts import render
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from account.renderers import userRenderer
from account.serializers import userserializer, userLoginSerializer, userProfileSerializer, \
    userChangePasswordSerializer, sendPasswordResetEmailserializer, UserPasswordResetSerializer


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class userRegistrationView(APIView):
    renderer_classes = [userRenderer]
    def post(self,request):
        serializer=userserializer(data=request.data)
        if serializer.is_valid():
            user=serializer.save()
            token=get_tokens_for_user(user)
            return Response({'token':token,'msg':'registration success'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class userLoginView(APIView):
    renderer_classes = [userRenderer]
    def post(self,request):
        serializer=userLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email=serializer.data.get('email')
            password=serializer.data.get('password')
            user=authenticate(email=email,password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token':token,"msg": "login Successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors':['email or password is not valid']}},status=status.HTTP_404_NOT_FOUND)
        else:
            Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class userProfileView(APIView):
    renderer_classes = [userRenderer]
    permission_classes = [IsAuthenticated]
    def get(self,request):
        serializer=userProfileSerializer(request.user)
        return Response(serializer.data,status=status.HTTP_200_OK)


class userChangePasswordView(APIView):
    renderer_classes = [userRenderer]
    permission_classes = [IsAuthenticated]
    def post(self,request):
        serializer= userChangePasswordSerializer(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password change '},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class sendPasswordResetEmailView(APIView):
    renderer_classes = [userRenderer]
    def post(self,request):
        serializer=sendPasswordResetEmailserializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password reset link send.'},status=status.HTTP_200_OK)
        return Response(serializer.errors)

class userPasswordResetView(APIView):
    renderer_classes = [userRenderer]
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Reset Successfully'}, status=status.HTTP_200_OK)

