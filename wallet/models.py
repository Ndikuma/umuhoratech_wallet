from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from .rpc_client import BitcoinRPCClient
import uuid

class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bitcoin_address = models.CharField(max_length=100, blank=True,null=True)
    balance = models.DecimalField(max_digits=16, decimal_places=8, default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Wallet"
    
    def update_balance(self):
        rpc = BitcoinRPCClient()
        self.balance = rpc.get_balance(self.user.username)
        self.save()
        return self.balance

class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('send', 'Send'),
        ('receive', 'Receive'),
    ]
    
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    txid = models.CharField(max_length=100, unique=True)
    amount = models.DecimalField(max_digits=16, decimal_places=8)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    address = models.CharField(max_length=100)
    confirmations = models.IntegerField(default=0)
    timestamp = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.transaction_type} - {self.amount} BTC"

@receiver(post_save, sender=User)
def create_user_wallet(sender, instance, created, **kwargs):
    if created:
        rpc = BitcoinRPCClient()
        address = rpc.get_new_address(instance.username)
        Wallet.objects.create(user=instance, bitcoin_address=address)