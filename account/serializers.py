from xml.dom import ValidationErr

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode




class userserializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model=User
        fields=['email','name','password','password2','tc']
        extra_kwargs={
            'password':{'write_only':True}
        }
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        print(password,password2)
        if password!=password2:
            raise serializers.ValidationError("password and conform doesn't match")
        return data

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)



class userLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']

class userProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','email','name']

class userChangePasswordSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    class Meta:
        fields=['password','password2']

    def validate(self, data):
        password=data.get('password')
        password2=data.get('password2')
        user=self.context.get('user')
        if password!=password2:
            raise serializers.ValidationError("passsword and conform password doesn't match")
        user.set_password(password)
        user.save()
        return data

class sendPasswordResetEmailserializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        fields=['email']

    def validate(self, data):
        email=data.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print('Encode UID',uid)
            token=PasswordResetTokenGenerator().make_token(user)
            print('password Reset Token',token)
            link='http://localhost:3000/api/user/reset/'+uid+'/'+token
            print('password reset link',link)
            return data


        else:
            raise ValidationErr('you are not a registerd user')


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, data):
        try:
            password = data.get('password')
            password2 = data.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password and Confirm Password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not Valid or Expired')
            user.set_password(password)
            user.save()
            return data
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')




