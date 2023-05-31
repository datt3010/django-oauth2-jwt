import datetime

import jwt
from django.contrib.auth import logout, authenticate
from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from django.shortcuts import render, redirect
from oauth2_provider.contrib.rest_framework import TokenHasScope
from rest_framework import generics
from rest_framework import permissions
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.sites.models import Site
from koolyard import settings
from .models import User
from .serializer import UserSerializer, GroupSerializer
from mptt.models import MPTTModel,TreeForeignKey


class CreateAccount(APIView):
    def post(self, request):
        reg_serializer = UserSerializer(data = request.data)
        if reg_serializer.is_valid():
            new_user = reg_serializer.save()
            if new_user:
                r = request.post('http://127.0.0.1:8000/api-auth/token', data={
                    'username': new_user.email,
                    'password': request.data['password'],
                    'client_id': '958211554068-kngdamcd895o00jlvqqjac5g2ubqa867.apps.googleusercontent.com',
                    'client_secret': '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',
                    'grant_type': 'password'
                })
                return Response(r.json(),status=status.HTTP_201_CREATED)
        return Response(reg_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def login(request):
    return render(request, 'login.html')
def home(request):
    return render(request,'home.html',{'user': request.user})

def logout_views(request):
    logout(request)
    return redirect("/")

class UserList(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserSerializer

class UserDetails(generics.RetrieveAPIView):
    permission_classes = []
    queryset = User.objects.all()
    serializer_class = UserSerializer

class GroupList(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated, TokenHasScope]
    required_scopes = ['groups']
    queryset = User.objects.all()
    serializer_class = GroupSerializer

class UserLoginView(APIView):
    authentication_classes = []
    permission_classes = []
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                request,
                email=serializer.validated_data['email'],
                password=serializer.validated_data['password']
            )
            if user:
                refresh = TokenObtainPairSerializer.get_token(user)
                data = {
                    'access_token': str(refresh.access_token),
                    'id_token': self.create_token(user),
                    'refresh_token': str(refresh),
                }
                return Response(data, status=status.HTTP_200_OK)

            return Response({
                'error_message': 'Email or password is incorrect!',
                'error_code': 400
            }, status=status.HTTP_400_BAD_REQUEST)
        print(serializer.errors)
        return Response({
            'error_messages': serializer.errors,
            'error_code': 400
        }, status=status.HTTP_400_BAD_REQUEST)

    def create_token(self,user):
        payload = {
            "user": {
                'id': user.id,
                'username': user.username,
                'email': user.email,
            },
            "iss": str(Site.objects.get_current().domain),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            "iat": datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        return token

class UserRegisterView(APIView):
    permission_classes = []
    authentication_classes = []
    def post(self, request):
        serializer = UserSerializer(data = request.data)
        if serializer.is_valid():
            serializer.validated_data['password'] = make_password(serializer.validated_data['password'])
            serializer.save()
            return JsonResponse({
                'message': 'Register successful',
            }, status = status.HTTP_201_CREATED)
        else:
            return JsonResponse({
                'error_message': 'This is email is already exists',
                'error_code': 400
            }, status = status.HTTP_400_BAD_REQUEST)
class UserView(APIView):
    permission_classes = []
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated')
        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)
class LogoutView(APIView):
    permission_classes = []
    def post(self,request):
        response = Response()
        response.delete_cookie('jwt')
        response.data={
            'message': 'logout is success'
        }
        return response
class UserListView(APIView):
    permission_classes = []
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated')
        user = User.objects.all()
        serializer = UserSerializer(user, many=True)
        return Response(serializer.data, status = status.HTTP_200_OK)


