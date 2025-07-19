from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Wallet, Transaction
from .rpc_client import BitcoinRPCClient
from .forms import UserRegistrationForm, TransactionForm
from django.db import transaction as db_transaction

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, 'Registration successful! Your wallet has been created.')
            return redirect('dashboard')
    else:
        form = UserRegistrationForm()
    return render(request, 'wallet/register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'wallet/login.html')

@login_required
def user_logout(request):
    logout(request)
    return redirect('login')

@login_required
def dashboard(request):
    wallet,_ = Wallet.objects.get_or_create(user=request.user)
    wallet.update_balance()
    
    rpc = BitcoinRPCClient()
    transactions = rpc.get_transactions(request.user.username, 5)
    
    # Sync transactions with our database
    for tx in transactions:
        Transaction.objects.get_or_create(
            txid=tx['txid'],
            defaults={
                'wallet': wallet,
                'amount': tx['amount'],
                'transaction_type': 'receive' if tx['amount'] > 0 else 'send',
                'address': tx['address'],
                'confirmations': tx.get('confirmations', 0),
                'timestamp': tx['time'],
            }
        )
    
    context = {
        'wallet': wallet,
        'transactions': wallet.transactions.order_by('-timestamp')[:5],
    }
    return render(request, 'wallet/dashboard.html', context)

@login_required
def transaction_history(request):
    wallet = Wallet.objects.get(user=request.user)
    transactions = wallet.transactions.order_by('-timestamp')
    return render(request, 'wallet/history.html', {'transactions': transactions})

@login_required
def send_transaction(request):
    wallet = Wallet.objects.get(user=request.user)
    wallet.update_balance()


    if request.method == 'POST':
        form = TransactionForm(request.POST)
        if form.is_valid():
            address = form.cleaned_data['address']
            amount = form.cleaned_data['amount']
            
            if amount > wallet.balance:
                messages.error(request, 'Insufficient balance.')
                return render(request, 'wallet/transaction.html', {'form': form, 'wallet': wallet})
            
            try:
                rpc = BitcoinRPCClient()
                txid = rpc.send_to_address(address, float(amount))
                
                if txid:
                    # Create transaction record
                    Transaction.objects.create(
                        wallet=wallet,
                        txid=txid,
                        amount=-amount,  # Negative for sent transactions
                        transaction_type='send',
                        address=address,
                        confirmations=0,
                        timestamp=timezone.now(),
                    )
                    
                    # Update wallet balance
                    wallet.update_balance()
                    
                    messages.success(request, f'Transaction successful! TXID: {txid}')
                    return redirect('dashboard')
                else:
                    messages.error(request, 'Transaction failed. Please try again.')
            except Exception as e:
                messages.error(request, f'Error: {str(e)}')
    else:
        form = TransactionForm()
    
    return render(request, 'wallet/transaction.html', {'form': form, 'wallet': wallet})