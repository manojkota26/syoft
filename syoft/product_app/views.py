# from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import generics, permissions, status
from rest_framework.decorators import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.db import IntegrityError
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login
from rest_framework.authtoken.models import Token
from . import serializers
from .models import CustomUser, Product
from django.contrib.auth.hashers import make_password, check_password


class Register(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, format=None):
        # Get the email, username, password, and role from the request data
        email = request.data.get('email')
        username = request.data.get('username')
        password = request.data.get('password')
        role = request.data.get('role')

        # Return an error if any of the required fields are missing
        if not email or not username or not password or not role:
            return Response({'status': False, 'error': 'Please provide all required fields'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Return an error if the role is not one of 'admin', 'manager', or 'staff'
        if role not in ['admin', 'manager', 'staff']:
            return Response({'status': False, 'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the email using EmailValidator
        validator = EmailValidator()
        try:
            validator(email)
        except ValidationError:
            return Response({'status': False, 'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

        # Attempt to create the user
        try:
            user = CustomUser.objects.create_user(username=username, password=password, email=email)
            user.role = role
            user.save()
            # Return a success message if the user is successfully created
            return Response({'status': True, 'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        except IntegrityError:
            # Return an error if the username or email is already in use
            return Response(
                {'status': False, 'error': 'Username or email already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )


class Login(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, format=None):
        email = request.data.get('email')
        plaintext_password = request.data.get('password')

        # Check if the email and password were provided
        if not email or not plaintext_password:
            return Response({'status': False, 'error': 'Please provide both email and password'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = CustomUser.objects.get(email=email)
            hashed_password = user.password
            # Check if the provided password matches the hashed password in the database
            is_password_correct = check_password(plaintext_password, hashed_password)
            if is_password_correct:
                # Create or retrieve a token for the user
                token, created = Token.objects.get_or_create(user=user)
                token_value = token.key
                return Response({'status': True, 'message': 'login successfully.', 'token': token_value}, status=status.HTTP_200_OK)
            else:
                return Response({'status': False, 'error': 'Invalid login. Please try again.'},
                                status=status.HTTP_400_BAD_REQUEST)

        except CustomUser.DoesNotExist:
            return Response({'status': False, 'error': 'Invalid login. Please try again.'},
                            status=status.HTTP_400_BAD_REQUEST)


class createProductView(generics.CreateAPIView):
    permission_classes = (permissions.IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        if request.user.role != 'admin':
            return Response({'status': False, 'error': 'You do not have permission to create products'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = serializers.ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            data = {'status': True, "result": serializer.data}
            return Response(data, status=status.HTTP_201_CREATED)
        data = {'status': False, "error": serializer.errors}
        return Response(data, status=status.HTTP_400_BAD_REQUEST)



class ProductDetailView(generics.GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request,  *args, **kwargs):
        if request.user.role not in ['admin', 'manager']:
            return Response({'status': False, 'error': 'You do not have permission to create products'}, status=status.HTTP_400_BAD_REQUEST)
        queryset = Product.objects.filter(is_active=True)
        serializer = serializers.ProductSerializer(queryset, many=True)
        data = {'status': True, "result": serializer.data}
        return Response(data, status=status.HTTP_200_OK)



class ProductDetailUpdateView(generics.UpdateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    queryset = Product.objects.all()
    lookup_field = "pk"

    def update(self, request,  *args, **kwargs):
        if request.user.role not in ['admin', 'manager']:
            return Response({'status': False, 'error': 'You do not have permission to create products'}, status=status.HTTP_400_BAD_REQUEST)
        product = get_object_or_404(Product, pk=self.kwargs['pk'])
        serializer = serializers.ProductSerializer(product, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteProductDetailView(generics.DestroyAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    queryset = Product.objects.all()
    lookup_field = "pk"

    def update(self, request,  *args, **kwargs):
        if request.user.role != 'admin':
            return Response({'status': False, 'error': 'You do not have permission to create products'}, status=status.HTTP_400_BAD_REQUEST)
        product = get_object_or_404(Product, pk=self.kwargs['pk'])
        product.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

