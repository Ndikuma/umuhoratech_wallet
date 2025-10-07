
### Blink API Integration Guide - Lightning Network Invoices, WebSocket Payment Confirmation and Sending to Lightning Address

## Table of Contents
1. [Overview](#1-Overview)
2. [Blink API Endpoints](#2-Blink_API_Endpoints)
3. [Authentication](#3-Authentication)
4. [Creating Lightning Network Invoices](#creating_lightning_network_invoices)
5. [WebSocket Payment Status Monitoring](#5-websocket_payment_status_monitoring)
6. [Polling Fallback Implementation](#6-Polling_Fallback_Implementation)
7. [Complete Implementation Example](#7-Complete_Implementation_Example)
8. [Error Handling](#8-Error_Handling)
9. [Best Practices](#9-Best_Practices)
10. [API Reference](#10-Api_Reference)
11. [Invoice Expiry Configuration](#11-Invoice_Expiry_Configuration)
12. [Blink API Integration for Lightning Address & Phone Number Payments](#12-Send_to_Lightning_Address)
## 1-Overview

This guide demonstrates how to integrate with the Blink API to:
- Generate Lightning Network invoices for Bitcoin payments
- Monitor payment status in real-time using WebSocket subscriptions
- Implement polling fallback for reliable payment confirmation
- Handle multi-currency support (Bitcoin/USD)

The Blink API uses GraphQL for all operations and provides both REST-like queries/mutations and real-time subscriptions via WebSocket.

## 2-Blink_API_Endpoints

### Main API Endpoint
- **GraphQL API**: `https://api.blink.sv/graphql`
- **WebSocket Subscriptions**: `wss://ws.blink.sv/graphql`
- **Protocol**: GraphQL over HTTP/WebSocket with `graphql-transport-ws` subprotocol

## 3-Authentication

The Blink API allows **public access** for certain operations:
- Creating invoices on behalf of recipients (using username)
- Fetching exchange rates
- Checking payment status

**No API keys or authentication tokens** are required for basic invoice generation and payment monitoring.

## Creating_Lightning_Network_Invoices

### Step 1: Get User's Default Wallet

First, retrieve the user's default wallet information using their Blink username:

```javascript
async function getAccountDefaultWallet(username) {
    const query = `
        query Query($username: Username!) {
            accountDefaultWallet(username: $username) {
                id
                currency
            }
        }
    `;
    
    const variables = { username: username };
    
    const response = await fetch('https://api.blink.sv/graphql', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            query,
            variables
        })
    });
    
    const data = await response.json();
    
    if (data.errors) {
        throw new Error(data.errors[0].message || 'Error fetching wallet info');
    }
    
    return data.data.accountDefaultWallet;
}
```

### Step 2: Create Invoice (BTC Wallet)

For Bitcoin wallets, use the BTC-specific mutation:

```javascript
async function createBTCInvoice(walletId, amountSats, memo) {
    const mutation = `
        mutation Mutation($input: LnInvoiceCreateOnBehalfOfRecipientInput!) {
            lnInvoiceCreateOnBehalfOfRecipient(input: $input) {
                invoice {
                    paymentRequest
                    satoshis
                }
            }
        }
    `;
    
    const variables = {
        input: {
            recipientWalletId: walletId,
            amount: amountSats.toString(),
            memo: memo,
            expiresIn: "15" // 15 minutes expiry
        }
    };
    
    const response = await fetch('https://api.blink.sv/graphql', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            query: mutation,
            variables
        })
    });
    
    const data = await response.json();
    
    if (data.errors) {
        throw new Error(data.errors[0].message || 'Error creating BTC invoice');
    }
    
    return {
        paymentRequest: data.data.lnInvoiceCreateOnBehalfOfRecipient.invoice.paymentRequest,
        expiryMinutes: 15
    };
}
```

### Step 3: Create Invoice (USD Wallet)

For USD wallets, use the USD-specific mutation:

```javascript
async function createUSDInvoice(walletId, amountCents, memo) {
    const mutation = `
        mutation LnUsdInvoiceCreateOnBehalfOfRecipient($input: LnUsdInvoiceCreateOnBehalfOfRecipientInput!) {
            lnUsdInvoiceCreateOnBehalfOfRecipient(input: $input) {
                invoice {
                    paymentRequest
                    satoshis
                }
            }
        }
    `;
    
    const variables = {
        input: {
            amount: amountCents.toString(),
            recipientWalletId: walletId,
            memo: memo,
            expiresIn: 5 // 5 minutes expiry for USD
        }
    };
    
    const response = await fetch('https://api.blink.sv/graphql', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            query: mutation,
            variables
        })
    });
    
    const data = await response.json();
    
    if (data.errors) {
        throw new Error(data.errors[0].message || 'Error creating USD invoice');
    }
    
    return {
        paymentRequest: data.data.lnUsdInvoiceCreateOnBehalfOfRecipient.invoice.paymentRequest,
        expiryMinutes: 5
    };
}
```

## 5-Websocket_Payment_Status_Monitoring

### Real-time Payment Confirmation

The most efficient way to monitor payment status is through WebSocket subscriptions:

```javascript
function subscribeToPaymentStatus(paymentRequest, onPaymentConfirmed) {
    // Connect to Blink WebSocket with graphql-transport-ws protocol
    const wsClient = new WebSocket('wss://ws.blink.sv/graphql', 'graphql-transport-ws');
    
    // Connection initialization message
    const initMessage = {
        type: 'connection_init',
        payload: {}
    };
    
    // Subscription message for payment status updates
    const subscriptionMsg = {
        id: '1',
        type: 'subscribe',
        payload: {
            query: `
                subscription LnInvoicePaymentStatusByPaymentRequest($input: LnInvoicePaymentStatusByPaymentRequestInput!) {
                    lnInvoicePaymentStatusByPaymentRequest(input: $input) {
                        paymentRequest
                        status
                    }
                }
            `,
            variables: {
                input: {
                    paymentRequest: paymentRequest
                }
            }
        }
    };
    
    // Handle WebSocket connection
    wsClient.onopen = () => {
        console.log('WebSocket connection established');
        
        // Send connection initialization
        wsClient.send(JSON.stringify(initMessage));
        
        // Send subscription after short delay
        setTimeout(() => {
            wsClient.send(JSON.stringify(subscriptionMsg));
        }, 500);
    };
    
    // Handle incoming messages
    wsClient.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            
            // Connection acknowledged
            if (data.type === 'connection_ack') {
                console.log('Connection acknowledged, subscription ready');
            }
            
            // Payment status update received
            if (data.type === 'data' && data.payload && data.payload.data) {
                const paymentStatus = data.payload.data.lnInvoicePaymentStatusByPaymentRequest;
                
                if (paymentStatus && paymentStatus.status === 'PAID') {
                    console.log('Payment confirmed via WebSocket! 🎉');
                    onPaymentConfirmed();
                    wsClient.close();
                }
            }
        } catch (error) {
            console.error('Error processing WebSocket message:', error);
        }
    };
    
    // Handle WebSocket errors - fallback to polling
    wsClient.onerror = (error) => {
        console.error('WebSocket error:', error);
        console.log('Falling back to polling...');
        pollPaymentStatus(paymentRequest, onPaymentConfirmed);
    };
    
    // Handle WebSocket closure
    wsClient.onclose = (event) => {
        console.log('WebSocket connection closed:', event.code, event.reason);
    };
    
    // Fallback timeout - switch to polling if no updates received
    setTimeout(() => {
        if (wsClient.readyState === WebSocket.OPEN) {
            console.log('No WebSocket updates received, falling back to polling');
            pollPaymentStatus(paymentRequest, onPaymentConfirmed);
        }
    }, 10000); // 10 second timeout
    
    return wsClient;
}
```

## 6-Polling_Fallback_Implementation
### Reliable Payment Status Checking

When WebSocket connections fail, implement polling as a fallback:

```javascript
function pollPaymentStatus(paymentRequest, onPaymentConfirmed) {
    console.log('Starting payment status polling...');
    
    const checkPaymentStatus = async () => {
        try {
            const query = `
                query CheckPaymentStatus($input: LnInvoicePaymentStatusInput!) {
                    lnInvoicePaymentStatus(input: $input) {
                        status
                    }
                }
            `;
            
            const variables = {
                input: {
                    paymentRequest: paymentRequest
                }
            };
            
            const response = await fetch('https://api.blink.sv/graphql', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query,
                    variables
                })
            });
            
            const data = await response.json();
            
            if (data.data && data.data.lnInvoicePaymentStatus) {
                const status = data.data.lnInvoicePaymentStatus.status;
                
                if (status === 'PAID') {
                    console.log('Payment confirmed via polling! 🎉');
                    onPaymentConfirmed();
                    return; // Stop polling
                }
            }
            
            // Continue polling if not yet paid
            setTimeout(checkPaymentStatus, 2000); // Poll every 2 seconds
            
        } catch (error) {
            console.error('Error polling payment status:', error);
            setTimeout(checkPaymentStatus, 5000); // Retry with longer interval on error
        }
    };
    
    // Start polling
    checkPaymentStatus();
}
```

## 7-Complete_Implementation_Example

### Full Integration Example

Here's a complete example that demonstrates the entire flow:

```javascript
class BlinkPaymentProcessor {
    constructor() {
        this.websocket = null;
    }
    
    async processPayment(username, amount, currency = 'sats', memo = 'Payment') {
        try {
            // Step 1: Get user's wallet information
            const walletInfo = await this.getAccountDefaultWallet(username);
            console.log('Wallet info:', walletInfo);
            
            // Step 2: Convert amount if needed
            let finalAmount = amount;
            let targetCurrency = walletInfo.currency;
            
            if (currency !== 'sats' && currency !== walletInfo.currency) {
                finalAmount = await this.convertCurrency(amount, currency, walletInfo.currency);
            }
            
            // Step 3: Create invoice
            const invoice = await this.createInvoice(
                walletInfo.id, 
                finalAmount, 
                targetCurrency, 
                memo
            );
            
            console.log('Invoice created:', invoice.paymentRequest.substring(0, 30) + '...');
            
            // Step 4: Start monitoring payment status
            this.monitorPayment(invoice.paymentRequest, () => {
                console.log('Payment successful!');
                this.onPaymentSuccess();
            });
            
            return {
                paymentRequest: invoice.paymentRequest,
                expiryMinutes: invoice.expiryMinutes
            };
            
        } catch (error) {
            console.error('Payment processing error:', error);
            throw error;
        }
    }
    
    async getAccountDefaultWallet(username) {
        // Implementation from previous examples
        // ... (see Step 1 above)
    }
    
    async createInvoice(walletId, amount, currency, memo) {
        if (currency === 'BTC') {
            return await this.createBTCInvoice(walletId, amount, memo);
        } else if (currency === 'USD') {
            return await this.createUSDInvoice(walletId, amount, memo);
        } else {
            throw new Error(`Unsupported currency: ${currency}`);
        }
    }
    
    async createBTCInvoice(walletId, amountSats, memo) {
        // Implementation from previous examples
        // ... (see Step 2 above)
    }
    
    async createUSDInvoice(walletId, amountCents, memo) {
        // Implementation from previous examples
        // ... (see Step 3 above)
    }
    
    monitorPayment(paymentRequest, onPaymentConfirmed) {
        // Try WebSocket first, fallback to polling
        this.websocket = this.subscribeToPaymentStatus(paymentRequest, onPaymentConfirmed);
    }
    
    subscribeToPaymentStatus(paymentRequest, onPaymentConfirmed) {
        // Implementation from previous examples
        // ... (see WebSocket section above)
    }
    
    pollPaymentStatus(paymentRequest, onPaymentConfirmed) {
        // Implementation from previous examples
        // ... (see Polling section above)
    }
    
    onPaymentSuccess() {
        // Handle successful payment
        if (this.websocket) {
            this.websocket.close();
            this.websocket = null;
        }
        
        // Add your success handling logic here
        console.log('Payment processing completed successfully!');
    }
    
    async convertCurrency(amount, fromCurrency, toCurrency) {
        // Get exchange rate and convert
        const rate = await this.getExchangeRate(fromCurrency);
        
        if (toCurrency === 'BTC') {
            // Convert to satoshis
            return Math.round(amount * rate.btcSatPrice.base * Math.pow(10, rate.btcSatPrice.offset));
        } else if (toCurrency === 'USD') {
            // Convert to cents
            return Math.round(amount * rate.usdCentPrice.base * Math.pow(10, rate.usdCentPrice.offset));
        }
        
        throw new Error(`Unsupported target currency: ${toCurrency}`);
    }
    
    async getExchangeRate(currencyCode) {
        const query = `
            query realtimePrice($currency: DisplayCurrency!) {
                realtimePrice(currency: $currency) {
                    btcSatPrice {
                        base
                        offset
                    }
                    usdCentPrice {
                        base
                        offset
                    }
                }
            }
        `;
        
        const variables = {
            currency: currencyCode.toUpperCase()
        };
        
        const response = await fetch('https://api.blink.sv/graphql', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                query,
                variables
            })
        });
        
        const data = await response.json();
        
        if (data.errors) {
            throw new Error(data.errors[0].message || 'Error fetching exchange rate');
        }
        
        return data.data.realtimePrice;
    }
}

// Usage Example
const processor = new BlinkPaymentProcessor();

processor.processPayment('satoshi', 1000, 'sats', 'Donation via website')
    .then(invoice => {
        console.log('Payment request:', invoice.paymentRequest);
        console.log('Expires in:', invoice.expiryMinutes, 'minutes');
    })
    .catch(error => {
        console.error('Failed to process payment:', error);
    });
```

## 8-Error_Handling

### Common Error Scenarios

```javascript
// Handle various error conditions
function handleBlinkAPIError(error, operation) {
    console.error(`${operation} failed:`, error);
    
    if (error.message.includes('User not found')) {
        return 'Invalid Blink username. Please check and try again.';
    } else if (error.message.includes('Invalid amount')) {
        return 'Invalid amount specified. Please enter a valid number.';
    } else if (error.message.includes('Network')) {
        return 'Network error. Please check your connection and try again.';
    } else if (error.message.includes('expired')) {
        return 'Invoice has expired. Please generate a new one.';
    } else {
        return 'An unexpected error occurred. Please try again later.';
    }
}

// Usage in your code
try {
    const wallet = await getAccountDefaultWallet(username);
} catch (error) {
    const userMessage = handleBlinkAPIError(error, 'Fetching user wallet');
    alert(userMessage);
}
```

## 9-Best_Practices

### 1. Connection Management
- Always implement WebSocket fallback to polling
- Set reasonable timeouts for WebSocket connections (10-15 seconds)
- Close WebSocket connections when payment is confirmed or cancelled

### 2. Error Handling
- Implement comprehensive error handling for network failures
- Provide user-friendly error messages
- Add retry logic with exponential backoff for transient failures

### 3. Performance Optimization
- Cache exchange rates for short periods (30-60 seconds)
- Use connection pooling for multiple requests
- Implement request debouncing for user input

### 4. Security Considerations
- Validate all user inputs before API calls
- Never expose sensitive data in client-side code
- Use HTTPS for all API communications

### 5. User Experience
- Show loading states during API calls
- Provide real-time feedback for payment status
- Implement proper timeout handling with user notifications

## 10-API_Reference

### GraphQL Queries

#### Get Account Default Wallet
```graphql
query Query($username: Username!) {
    accountDefaultWallet(username: $username) {
        id
        currency
    }
}
```

#### Get Exchange Rate
```graphql
query realtimePrice($currency: DisplayCurrency!) {
    realtimePrice(currency: $currency) {
        btcSatPrice {
            base
            offset
        }
        usdCentPrice {
            base
            offset
        }
    }
}
```

#### Check Payment Status (Polling)
```graphql
query CheckPaymentStatus($input: LnInvoicePaymentStatusInput!) {
    lnInvoicePaymentStatus(input: $input) {
        status
    }
}
```

### GraphQL Mutations

#### Create BTC Invoice
```graphql
mutation Mutation($input: LnInvoiceCreateOnBehalfOfRecipientInput!) {
    lnInvoiceCreateOnBehalfOfRecipient(input: $input) {
        invoice {
            paymentRequest
            satoshis
        }
    }
}
```

#### Create USD Invoice
```graphql
mutation LnUsdInvoiceCreateOnBehalfOfRecipient($input: LnUsdInvoiceCreateOnBehalfOfRecipientInput!) {
    lnUsdInvoiceCreateOnBehalfOfRecipient(input: $input) {
        invoice {
            paymentRequest
            satoshis
        }
    }
}
```

### GraphQL Subscriptions

#### Payment Status Updates
```graphql
subscription LnInvoicePaymentStatusByPaymentRequest($input: LnInvoicePaymentStatusByPaymentRequestInput!) {
    lnInvoicePaymentStatusByPaymentRequest(input: $input) {
        paymentRequest
        status
    }
}
```

## 11-Invoice_Expiry_Configuration

### Overview

Lightning Network invoices have configurable expiry times to ensure payment security and prevent indefinite pending states. The Blink API allows you to set custom expiry times when creating invoices, with different defaults for different wallet currencies.

### Setting Custom Expiry Times

#### For BTC Invoices

You can specify custom expiry times using the expiresIn parameter (in minutes):

### Default Expiry Times

The Blink API uses a default expiry time for USD wallet:

- USD Wallets: 5 minutes (300 seconds)

### Supported Currencies

The Blink API supports 30+ fiat currencies for exchange rate conversion:

**Major Currencies**: USD, EUR, GBP, JPY, CAD, AUD, CHF, CNY  
**Regional Currencies**: ZAR, BRL, MXN, INR, KRW, SGD, THB, PHP  
**African Currencies**: NGN, KES, GHS, UGX, TZS, RWF, ETB  
**Other Currencies**: NOK, SEK, DKK, PLN, CZK, HUF, TRY, ILS, AED, SAR

### Rate Limits and Constraints


- **Amount Limits**: Check with Blink for current limits
- **Rate Limiting**: No specific rate limits documented for public endpoints
- **WebSocket Connections**: Limit concurrent connections per client

---

## 12-Send_to_Lightning_Address 

Blink API Integration for Lightning Address & Phone Number Payments

## Overview

This project implements a robust Lightning payment system using the Blink API that supports both Lightning Addresses and phone numbers. The system converts phone numbers to Lightning Addresses (format: `phonenumber@blink.sv`) and handles payments through GraphQL mutations.

## Core Implementation

### 1. Blink Service (`server/src/services/blink.ts`)

The main service class handles all Blink API interactions:

```typescript
interface RewardParams {
  destination: string;   // Lightning Address or phone@blink.sv
  amountSats: number;    // Amount in satoshis
  memo?: string;         // Optional memo
}

interface RewardResult {
  success: boolean;
  transactionId?: string;
  error?: string;
}

class BlinkService {
  private apiUrl: string = 'https://api.blink.sv/graphql';
  private apiKey: string;
  private walletId: string = "56c2e2d3-127f-4563-a5ef-a1dc599c8b27";

  // Main payment method for Lightning Addresses
  public async sendBitcoinReward(params: RewardParams): Promise<RewardResult> {
    const mutation = `
      mutation LnAddressPaymentSend($input: LnAddressPaymentSendInput!) {
        lnAddressPaymentSend(input: $input) {
          status
          errors {
            message
          }
        }
      }
    `;

    const variables = {
      input: {
        amount: params.amountSats,
        lnAddress: params.destination,
        walletId: this.walletId
      }
    };

    const response = await axios.post(this.apiUrl, {
      query: mutation,
      variables
    }, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': this.apiKey
      }
    });

    // Handle response and return success/error
    return {
      success: response.data.data.lnAddressPaymentSend.status === 'SUCCESS',
      transactionId: `payment_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`
    };
  }
}
```

### 2. Phone Number Integration

The system automatically converts phone numbers to Lightning Addresses:

```typescript
// In paparaController.ts
export const createPayment = async (req: Request, res: Response) => {
  const { amount, lightningAddress, phoneNumber, productNumber } = req.body;

  // Clean phone number if provided
  let cleanPhoneNumber = '';
  if (phoneNumber) {
    cleanPhoneNumber = phoneNumber.replace(/\D/g, ''); // Remove non-digits
  }

  // Convert phone number to Lightning Address
  let finalLightningAddress = lightningAddress;
  if (!finalLightningAddress && cleanPhoneNumber) {
    finalLightningAddress = cleanPhoneNumber + '@blink.sv';
  }

  // Store both original phone number and derived Lightning Address
  await dbService.updatePaparaPayment(paymentId, {
    lightning_address: finalLightningAddress,
    phone_number: cleanPhoneNumber || undefined,
    // ... other fields
  });
};
```

### 3. Lightning Address Validation

```typescript
// In lightningController.ts
export const checkLightningAddressExists = async (req: Request, res: Response) => {
  const { lightningAddress } = req.body;
  
  // Extract username and domain
  const [username, domain] = lightningAddress.split('@');
  
  // Check LNURL endpoint
  const lnurlEndpoint = `https://${domain}/.well-known/lnurlp/${username}`;
  
  const response = await axios.get(lnurlEndpoint, { timeout: 5000 });
  
  // Validate response contains required fields
  if (response.data && response.data.callback && response.data.tag === 'payRequest') {
    return res.json({
      success: true,
      message: 'Lightning address exists'
    });
  }
};
```

## Complete Integration Examples

### 1. Basic Lightning Address Payment

```typescript
import { blinkService } from '../services/blink';

async function sendToLightningAddress(address: string, amountSats: number) {
  try {
    const result = await blinkService.sendBitcoinReward({
      destination: address,
      amountSats: amountSats
    });

    if (result.success) {
      console.log('Payment successful:', result.transactionId);
      return { success: true, txId: result.transactionId };
    } else {
      console.error('Payment failed:', result.error);
      return { success: false, error: result.error };
    }
  } catch (error) {
    console.error('Payment error:', error);
    return { success: false, error: error.message };
  }
}
```

### 2. Phone Number Payment (Auto-conversion)

```typescript
async function sendToPhoneNumber(phoneNumber: string, amountSats: number) {
  // Clean and format phone number
  const cleanPhone = phoneNumber.replace(/[\s\-\+\(\)]/g, '');
  const lightningAddress = `${cleanPhone}@blink.sv`;

  return await blinkService.sendBitcoinReward({
    destination: lightningAddress,
    amountSats: amountSats
  });
}
```

### 3. Full Payment Flow with Database Integration

```typescript
const processLightningPayment = async (
  paymentId: string,
  lightningAddress: string,
  tryAmount: number
) => {
  try {
    // Prevent duplicate payments
    const markResult = await dbService.checkAndMarkPaymentInProgress(paymentId);
    if (!markResult) {
      console.log('Payment already in progress');
      return false;
    }

    // Get BTC/TRY exchange rate
    const btcTryRate = await getBtcTryRate();
    
    // Convert TRY to satoshis
    const satoshiAmount = tryToSats(tryAmount, btcTryRate);

    // Send Bitcoin payment
    const sendResult = await blinkService.sendBitcoinReward({
      destination: lightningAddress,
      amountSats: satoshiAmount
    });

    // Update database with results
    await dbService.updateBlinkPayment(paymentId, {
      blink_payment_hash: null,
      blink_amount_sats: satoshiAmount,
      blink_succeeded: sendResult.success,
      btc_try_rate: btcTryRate,
      blink_error: sendResult.error,
      blink_transaction_id: sendResult.transactionId
    });

    return sendResult.success;
  } catch (error) {
    console.error('Lightning payment error:', error);
    return false;
  }
};
```

## Configuration Setup

### 1. Environment Variables

```bash
# .env file
BLINK_API_URL=https://api.blink.sv/graphql
BLINK_API_KEY=blink_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
BASE_URL=https://turuncuhap.com
```

### 2. Configuration Module

```typescript
// config/index.ts
import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: process.env.PORT || 3001,
  blinkApiUrl: process.env.BLINK_API_URL || 'https://api.blink.sv/graphql',
  blinkApiKey: process.env.BLINK_API_KEY || '',
  baseUrl: process.env.BASE_URL || 'https://turuncuhap.com'
};
```

## Available Blink API Methods

### 1. Lightning Address Payment (`LnAddressPaymentSend`)

```graphql
mutation LnAddressPaymentSend($input: LnAddressPaymentSendInput!) {
  lnAddressPaymentSend(input: $input) {
    status
    errors {
      message
    }
  }
}
```

**Input Fields:**
- `amount`: Number (satoshis)
- `lnAddress`: String (Lightning Address)
- `walletId`: String (Your wallet ID)

### 2. Intra-Ledger Payment (`IntraLedgerPaymentSend`)

For payments between Blink users (like phone numbers):

```graphql
mutation IntraLedgerPaymentSend($input: IntraLedgerPaymentSendInput!) {
  intraLedgerPaymentSend(input: $input) {
    status
    errors {
      message
    }
  }
}
```

### 3. Wallet Balance Query

```graphql
query BTCWallet {
  me {
    defaultAccount {
      wallets {
        ... on BTCWallet {
          balance
        }
      }
    }
  }
}
```

### 4. Exchange Rate Query

```graphql
query Query($currency: DisplayCurrency) {
  realtimePrice(currency: $currency) {
    btcSatPrice {
      base
      offset
    }
  }
}
```

## Best Practices

### 1. Error Handling

```typescript
try {
  const result = await blinkService.sendBitcoinReward(params);
  
  if (result.success) {
    // Handle success
  } else {
    // Handle known errors
    console.error('Payment failed:', result.error);
  }
} catch (error) {
  if (axios.isAxiosError(error)) {
    console.error('API Error:', error.response?.data);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

### 2. Phone Number Validation

```typescript
function validatePhoneNumber(phoneNumber: string): boolean {
  // Remove all non-digits and check length
  const cleaned = phoneNumber.replace(/\D/g, '');
  return cleaned.length >= 10 && cleaned.length <= 15;
}
```

### 3. Lightning Address Validation

```typescript
function isValidLightningAddressFormat(address: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address);
}
```

### 4. Amount Conversion

```typescript
function tryToSats(tryAmount: number, btcTryRate: number): number {
  const btcAmount = tryAmount / btcTryRate;
  return Math.floor(btcAmount * 100000000); // Convert to satoshis
}
```

### 5. Duplicate Payment Prevention

```typescript
export const checkAndMarkPaymentInProgress = async (paymentId: string): Promise<boolean> => {
  const database = await getDb();
  
  await database.exec('BEGIN IMMEDIATE TRANSACTION');
  
  try {
    const existing = await database.get(
      'SELECT payment_in_progress, blink_succeeded FROM payments WHERE papara_payment_id = ?',
      [paymentId]
    );

    if (existing?.payment_in_progress || existing?.blink_succeeded) {
      await database.exec('ROLLBACK');
      return false;
    }

    await database.run(
      'UPDATE payments SET payment_in_progress = 1 WHERE papara_payment_id = ?',
      [paymentId]
    );

    await database.exec('COMMIT');
    return true;
  } catch (error) {
    await database.exec('ROLLBACK');
    throw error;
  }
};
```

## Testing

### Example Test Cases

```typescript
// Test Lightning Address payment
await sendToLightningAddress('ideasarelikeflames@blink.sv', 100);

// Test phone number payment
await sendToPhoneNumber('+1234567890', 100);

// Test invalid addresses
await sendToLightningAddress('invalid@domain.com', 100); // Should fail gracefully
```

