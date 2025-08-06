"""
Custom permissions for Bitcoin Mini Wallet API.
"""

from rest_framework import permissions
from rest_framework.request import Request
from rest_framework.views import View
from django.contrib.auth.models import User
from .models import Wallet, Transaction


class IsWalletOwner(permissions.BasePermission):
    """
    Permission to only allow owners of a wallet to access it.
    """
    
    message = "You can only access your own wallet."
    
    def has_object_permission(self, request: Request, view: View, obj) -> bool:
        """
        Check if the user owns the wallet.
        """
        if isinstance(obj, Wallet):
            return obj.user == request.user
        elif isinstance(obj, Transaction):
            return obj.wallet.user == request.user
        return False


class IsWalletOwnerOrReadOnly(permissions.BasePermission):
    """
    Permission to allow read access to anyone, but write access only to wallet owners.
    """
    
    message = "You can only modify your own wallet."
    
    def has_object_permission(self, request: Request, view: View, obj) -> bool:
        """
        Read permissions for any request, write permissions only for wallet owners.
        """
        # Read permissions for any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions only for wallet owners
        if isinstance(obj, Wallet):
            return obj.user == request.user
        elif isinstance(obj, Transaction):
            return obj.wallet.user == request.user
        return False


class IsActiveUser(permissions.BasePermission):
    """
    Permission to only allow active users to access the API.
    """
    
    message = "Your account is inactive. Please contact support."
    
    def has_permission(self, request: Request, view: View) -> bool:
        """
        Check if the user is active.
        """
        return request.user and request.user.is_authenticated and request.user.is_active


class HasActiveWallet(permissions.BasePermission):
    """
    Permission to only allow users with active wallets to perform wallet operations.
    """
    
    message = "Your wallet is inactive. Please contact support."
    
    def has_permission(self, request: Request, view: View) -> bool:
        """
        Check if the user has an active wallet.
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            wallet = request.user.wallet
            return wallet.is_active
        except Wallet.DoesNotExist:
            return False


class CanSendTransactions(permissions.BasePermission):
    """
    Permission to allow transaction sending only for verified users with active wallets.
    """
    
    message = "You don't have permission to send transactions."
    
    def has_permission(self, request: Request, view: View) -> bool:
        """
        Check if the user can send transactions.
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Check if user is active
        if not request.user.is_active:
            return False
        
        # Check if user has an active wallet
        try:
            wallet = request.user.wallet
            return wallet.is_active
        except Wallet.DoesNotExist:
            return False


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission to allow access to owners or admin users.
    """
    
    message = "You can only access your own resources or you must be an admin."
    
    def has_object_permission(self, request: Request, view: View, obj) -> bool:
        """
        Check if the user is the owner or an admin.
        """
        # Admin users have full access
        if request.user.is_staff or request.user.is_superuser:
            return True
        
        # Check ownership based on object type
        if isinstance(obj, User):
            return obj == request.user
        elif isinstance(obj, Wallet):
            return obj.user == request.user
        elif isinstance(obj, Transaction):
            return obj.wallet.user == request.user
        
        return False


class ReadOnlyOrOwner(permissions.BasePermission):
    """
    Permission to allow read-only access to everyone, but write access only to owners.
    """
    
    def has_permission(self, request: Request, view: View) -> bool:
        """
        Allow read access to authenticated users.
        """
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request: Request, view: View, obj) -> bool:
        """
        Read permissions for authenticated users, write permissions for owners only.
        """
        # Read permissions for authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions only for owners
        if isinstance(obj, Wallet):
            return obj.user == request.user
        elif isinstance(obj, Transaction):
            return obj.wallet.user == request.user
        
        return False