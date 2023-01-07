from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response

def custom_exception_handler(exc, context):
    if isinstance(exc, AuthenticationFailed):
        return Response({'error': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)
    return None
