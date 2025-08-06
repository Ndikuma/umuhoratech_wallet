"""
API-only views for Bitcoin Mini Wallet.
This file contains only custom error handlers for the API.
"""

from django.http import JsonResponse
from django.utils import timezone


# Custom error handlers for API
def custom_400(request, exception=None):
    """Custom 400 Bad Request handler."""
    from django.http import JsonResponse
    return JsonResponse({
        'success': False,
        'error': {
            'code': 400,
            'message': 'Bad Request',
            'details': 'The request could not be understood by the server.'
        }
    }, status=400)


def custom_403(request, exception=None):
    """Custom 403 Forbidden handler."""
    from django.http import JsonResponse
    return JsonResponse({
        'success': False,
        'error': {
            'code': 403,
            'message': 'Forbidden',
            'details': 'You do not have permission to access this resource.'
        }
    }, status=403)


def custom_404(request, exception=None):
    """Custom 404 Not Found handler."""
    from django.http import JsonResponse
    return JsonResponse({
        'success': False,
        'error': {
            'code': 404,
            'message': 'Not Found',
            'details': 'The requested resource was not found.'
        }
    }, status=404)


def custom_500(request):
    """Custom 500 Internal Server Error handler."""
    from django.http import JsonResponse
    return JsonResponse({
        'success': False,
        'error': {
            'code': 500,
            'message': 'Internal Server Error',
            'details': 'An unexpected error occurred. Please try again later.'
        }
    }, status=500)