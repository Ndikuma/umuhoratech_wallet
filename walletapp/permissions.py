from rest_framework import permissions
from .models import *

class IsWalletOwner(permissions.BasePermission):
    """Check if the user owns the wallet."""
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user

class IsActiveUser(permissions.BasePermission):
    """Check if the user is active."""
    def has_permission(self, request, view):
        return request.user.is_active

class HasActiveWallet(permissions.BasePermission):
    """Check if the user has an active wallet."""
    def has_permission(self, request, view):
        return Wallet.objects.filter(user=request.user, bitcoin_address__isnull=False).exists()

class CanSendTransactions(permissions.BasePermission):
    """Check if the user can send transactions."""
    def has_permission(self, request, view):
        try:
            wallet = Wallet.objects.get(user=request.user)
            balance = wallet.service.get_balance()
            return balance['btc'] > 0
        except Exception:
            return False