from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator

class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

class TransactionForm(forms.Form):
    address = forms.CharField(
        label='Recipient Address',
        max_length=100,
        widget=forms.TextInput(attrs={'placeholder': 'Enter Bitcoin address'})
    )
    amount = forms.DecimalField(
        label='Amount (BTC)',
        max_digits=16,
        decimal_places=8,
        validators=[MinValueValidator(0.00001)],
        widget=forms.NumberInput(attrs={'placeholder': '0.00000000'})
    )