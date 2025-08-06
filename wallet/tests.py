"""
Comprehensive test suite for Bitcoin Mini Wallet API.
"""

import json
from decimal import Decimal
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.conf import settings

from .models import Wallet, Transaction
from .serializers import (
    UserRegistrationSerializer, WalletSerializer, TransactionSerializer
)
from .utils import validate_bitcoin_address, is_valid_transaction_amount
from .rpc_client import BitcoinRPCClient


class UtilsTestCase(TestCase):
    """Test utility functions."""
    
    def test_validate_bitcoin_address(self):
        """Test Bitcoin address validation."""
        # Valid addresses
        valid_addresses = [
            '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',  # Legacy
            '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',  # P2SH
            'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',  # Bech32
        ]
        
        for address in valid_addresses:
            self.assertTrue(validate_bitcoin_address(address))
        
        # Invalid addresses
        invalid_addresses = [
            '',
            'invalid',
            '1234567890',
            'bc1invalid',
        ]
        
        for address in invalid_addresses:
            self.assertFalse(validate_bitcoin_address(address))
    
    def test_is_valid_transaction_amount(self):
        """Test transaction amount validation."""
        min_amount = Decimal(str(settings.WALLET_SETTINGS['MIN_TRANSACTION_AMOUNT']))
        
        # Valid amounts
        self.assertTrue(is_valid_transaction_amount(min_amount))
        self.assertTrue(is_valid_transaction_amount(Decimal('0.001')))
        self.assertTrue(is_valid_transaction_amount(Decimal('1.0')))
        
        # Invalid amounts
        self.assertFalse(is_valid_transaction_amount(Decimal('0')))
        self.assertFalse(is_valid_transaction_amount(min_amount - Decimal('0.00000001')))


class ModelTestCase(TestCase):
    """Test model functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_wallet_creation(self):
        """Test wallet creation."""
        wallet = Wallet.objects.create_wallet_for_user(self.user)
        
        self.assertEqual(wallet.user, self.user)
        self.assertTrue(wallet.wallet_name.startswith('user_'))
        self.assertEqual(wallet.balance, Decimal('0'))
        self.assertTrue(wallet.is_active)
    
    def test_wallet_str_representation(self):
        """Test wallet string representation."""
        wallet = Wallet.objects.create(
            user=self.user,
            wallet_name='test_wallet',
            balance=Decimal('0.5')
        )
        
        expected = f"{self.user.username}'s Wallet (0.50000000 BTC)"
        self.assertEqual(str(wallet), expected)
    
    def test_transaction_creation(self):
        """Test transaction creation."""
        wallet = Wallet.objects.create(
            user=self.user,
            wallet_name='test_wallet'
        )
        
        transaction = Transaction.objects.create(
            wallet=wallet,
            txid='a' * 64,
            amount=Decimal('0.1'),
            transaction_type='receive',
            address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            confirmations=6,
            timestamp='2023-01-01T00:00:00Z'
        )
        
        self.assertEqual(transaction.wallet, wallet)
        self.assertEqual(transaction.amount, Decimal('0.1'))
        self.assertTrue(transaction.is_confirmed)
        self.assertEqual(transaction.status, 'confirmed')


class SerializerTestCase(TestCase):
    """Test serializer functionality."""
    
    def test_user_registration_serializer(self):
        """Test user registration serializer."""
        data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        }
        
        serializer = UserRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        user = serializer.save()
        self.assertEqual(user.username, 'newuser')
        self.assertEqual(user.email, 'new@example.com')
    
    def test_user_registration_serializer_password_mismatch(self):
        """Test user registration with password mismatch."""
        data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'newpass123',
            'password_confirm': 'different123'
        }
        
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password_confirm', serializer.errors)


class APITestCase(APITestCase):
    """Test API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.wallet = Wallet.objects.create_wallet_for_user(self.user)
    
    def authenticate(self):
        """Authenticate the test client."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
    
    def test_api_root(self):
        """Test API root endpoint."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        data = response.json()
        self.assertEqual(data['name'], 'Bitcoin Mini Wallet API')
        self.assertIn('endpoints', data)
    
    def test_user_registration(self):
        """Test user registration endpoint."""
        url = '/api/v1/auth/register/'
        data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('token', response_data['data'])
        self.assertIn('user', response_data['data'])
        self.assertIn('wallet', response_data['data'])
    
    def test_user_login(self):
        """Test user login endpoint."""
        url = '/api/v1/auth/login/'
        data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('token', response_data['data'])
    
    def test_user_login_invalid_credentials(self):
        """Test user login with invalid credentials."""
        url = '/api/v1/auth/login/'
        data = {
            'username': 'testuser',
            'password': 'wrongpass'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        response_data = response.json()
        self.assertFalse(response_data['success'])
    
    def test_user_logout(self):
        """Test user logout endpoint."""
        self.authenticate()
        url = '/api/v1/auth/logout/'
        
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
    
    def test_wallet_detail(self):
        """Test wallet detail endpoint."""
        self.authenticate()
        url = f'/api/v1/wallets/{self.wallet.id}/'
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('wallet_name', response_data['data'])
    
    def test_wallet_balance(self):
        """Test wallet balance endpoint."""
        self.authenticate()
        url = '/api/v1/wallets/balance/'
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('balance', response_data['data'])
    
    @patch('wallet.models.Wallet.update_balance')
    def test_wallet_update_balance(self, mock_update):
        """Test wallet balance update endpoint."""
        mock_update.return_value = Decimal('0.5')
        
        self.authenticate()
        url = '/api/v1/wallets/update_balance/'
        
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        mock_update.assert_called_once()
    
    @patch('wallet.models.Wallet.generate_new_address')
    def test_wallet_generate_address(self, mock_generate):
        """Test address generation endpoint."""
        mock_generate.return_value = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        
        self.authenticate()
        url = '/api/v1/wallets/generate_address/'
        data = {'label': 'test_address'}
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('address', response_data['data'])
        mock_generate.assert_called_once_with('test_address')
    
    def test_transaction_list(self):
        """Test transaction list endpoint."""
        self.authenticate()
        
        # Create test transaction
        Transaction.objects.create(
            wallet=self.wallet,
            txid='a' * 64,
            amount=Decimal('0.1'),
            transaction_type='receive',
            address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            timestamp='2023-01-01T00:00:00Z'
        )
        
        url = '/api/v1/transactions/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(len(response_data['data']), 1)
    
    @patch('wallet.models.Wallet.send_transaction')
    def test_send_transaction(self, mock_send):
        """Test send transaction endpoint."""
        mock_send.return_value = 'a' * 64
        
        # Create transaction object that would be returned
        transaction = Transaction.objects.create(
            wallet=self.wallet,
            txid='a' * 64,
            amount=Decimal('-0.1'),
            transaction_type='send',
            address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            timestamp='2023-01-01T00:00:00Z'
        )
        
        self.authenticate()
        url = '/api/v1/transactions/send/'
        data = {
            'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'amount': '0.1',
            'comment': 'Test transaction'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        mock_send.assert_called_once()
    
    def test_send_transaction_invalid_address(self):
        """Test send transaction with invalid address."""
        self.authenticate()
        url = '/api/v1/transactions/send/'
        data = {
            'address': 'invalid_address',
            'amount': '0.1'
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        response_data = response.json()
        self.assertFalse(response_data['success'])
    
    @patch('wallet.models.Wallet.sync_transactions')
    def test_sync_transactions(self, mock_sync):
        """Test transaction sync endpoint."""
        mock_sync.return_value = 5
        
        self.authenticate()
        url = '/api/v1/transactions/sync/'
        data = {'limit': 50}
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['data']['synced_count'], 5)
        mock_sync.assert_called_once()
    
    def test_unauthorized_access(self):
        """Test unauthorized access to protected endpoints."""
        url = '/api/v1/wallets/balance/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_user_profile(self):
        """Test user profile endpoint."""
        self.authenticate()
        url = '/api/v1/users/profile/'
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['data']['username'], 'testuser')


class BitcoinRPCTestCase(TestCase):
    """Test Bitcoin RPC client."""
    
    @patch('wallet.rpc_client.AuthServiceProxy')
    def test_rpc_client_initialization(self, mock_proxy):
        """Test RPC client initialization."""
        mock_connection = MagicMock()
        mock_proxy.return_value = mock_connection
        mock_connection.getblockchaininfo.return_value = {'blocks': 100}
        
        client = BitcoinRPCClient('test_wallet')
        connection = client.connection
        
        self.assertIsNotNone(connection)
        mock_connection.getblockchaininfo.assert_called_once()
    
    @patch('wallet.rpc_client.AuthServiceProxy')
    def test_get_balance(self, mock_proxy):
        """Test get balance functionality."""
        mock_connection = MagicMock()
        mock_proxy.return_value = mock_connection
        mock_connection.getblockchaininfo.return_value = {'blocks': 100}
        mock_connection.getbalance.return_value = 0.5
        
        client = BitcoinRPCClient('test_wallet')
        balance = client.get_balance()
        
        self.assertEqual(balance, Decimal('0.5'))
        mock_connection.getbalance.assert_called_once()


class IntegrationTestCase(TransactionTestCase):
    """Integration tests for the complete API workflow."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
    
    def test_complete_user_workflow(self):
        """Test complete user workflow from registration to transaction."""
        # 1. Register user
        register_data = {
            'username': 'integrationuser',
            'email': 'integration@example.com',
            'password': 'integrationpass123',
            'password_confirm': 'integrationpass123'
        }
        
        response = self.client.post('/api/v1/auth/register/', register_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        token = response.json()['data']['token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        
        # 2. Get wallet details
        response = self.client.get('/api/v1/wallets/balance/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 3. Get transaction history
        response = self.client.get('/api/v1/transactions/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 4. Get user profile
        response = self.client.get('/api/v1/users/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 5. Logout
        response = self.client.post('/api/v1/auth/logout/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
