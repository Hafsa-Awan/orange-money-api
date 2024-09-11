const express = require('express');
const fetch = require('node-fetch');
const bodyParser = require('body-parser');
const NodeRSA = require('node-rsa');  // Import the Node-RSA library

const app = express();
app.use(bodyParser.json());

const client_id = process.env.CLIENT_ID;
const client_secret = process.env.CLIENT_SECRET;


// Endpoint to obtain the access token
app.post('/getAccessToken', async (req, res) => {
    try {
        const response = await fetch('https://api.sandbox.orange-sonatel.com/oauth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `grant_type=client_credentials&client_id=${client_id}&client_secret=${client_secret}`,
        });

        const data = await response.json();
        
        // Log the full response and data for debugging
        console.log('Response status:', response.status);
        console.log('Response body:', data);

        if (response.status === 200) {
            res.json({ accessToken: data.access_token });
        } else {
            res.status(response.status).json({ 
                error: 'Failed to get access token', 
                details: data 
            });
        }
    } catch (error) {
        console.error('Error fetching access token:', error);  // Log the error for debugging
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Endpoint to get the public key for PIN encryption
app.post('/getPublicKey', async (req, res) => {
    const { accessToken } = req.body;

    try {
        const response = await fetch('https://api.sandbox.orange-sonatel.com/api/account/v1/publicKeys', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
        });

        const data = await response.json();
        if (response.status === 200) {
            res.json({ key: data.key });
        } else {
            res.status(response.status).json({ error: 'Failed to fetch public key' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Endpoint to generate a test number
app.get('/generateTestNumber', async (req, res) => {
    // Get the access token from the Authorization header, and strip the 'Bearer ' prefix
    const authorizationHeader = req.headers.authorization;
    const accessToken = authorizationHeader && authorizationHeader.split(' ')[1]; // Extract the token

    const { nbMerchants, nbCustomers } = req.query; // Extract query parameters from the URL

    if (!accessToken) {
        return res.status(401).json({ error: 'Missing or invalid access token' });
    }

    try {
        const response = await fetch(`https://api.sandbox.orange-sonatel.com/api/assignments/v1/partner/sim-cards?nbMerchants=${nbMerchants}&nbCustomers=${nbCustomers}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`, // Pass the access token here
                'Content-Type': 'application/json',
            },
        });

        const data = await response.json();
        if (response.status === 200) {
            res.json({ msisdn: data[1].msisdn, pinCode: data[1].pinCode });
        } else {
            res.status(response.status).json({ error: 'Failed to generate test number' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});


// Endpoint to encrypt PIN using the public key

const crypto = require('crypto');

app.post('/encryptPin', (req, res) => {
    const { key, pinCode } = req.body;

    try {
        // Ensure the public key is in the correct PEM format
        const publicKey = `-----BEGIN PUBLIC KEY-----
$key
-----END PUBLIC KEY-----`;

         const publicKeyInstance = new NodeRSA(publicKey);
          publicKeyInstance.importKey(publicKey, 'pkcs8-public');
    const encryptedPin = publicKeyInstance.encrypt(pinCode, 'base64');
    

        // Respond with the encrypted PIN in base64 format
        res.json({ encryptedPin: encryptedPin });
    } catch (error) {
        res.status(500).json({ error: 'Encryption error: ' + error.message });
    }
});



// Endpoint to request OTP
app.post('/requestOtp', async (req, res) => {
        const authorizationHeader = req.headers.authorization;
    const accessToken = authorizationHeader && authorizationHeader.split(' ')[1];
    const { msisdn, encryptedPinCode } = req.body;

    try {
        const response = await fetch('https://api.sandbox.orange-sonatel.com/api/eWallet/v1/payments/otp', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ idType: 'MSISDN', id: msisdn, encryptedPinCode: encryptedPinCode}),
        });

        const data = await response.json();
        if (response.status === 200) {
            res.json({ otp: data.otp });
        } else {
            res.status(response.status).json({ error: 'Failed to request OTP' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Endpoint to perform one-step payment
app.post('/performOneStepPayment', async (req, res) => {
    const { otp, msisdn, merchantCode, amount, correlationId, accessToken } = req.body;

    try {
        const response = await fetch('https://api.sandbox.orange-sonatel.com/api/eWallet/v1/payments/onestep', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                customer: {
                    idType: 'MSISDN',
                    id: msisdn,
                    otp: otp
                },
                partner: {
                    idType: 'CODE',
                    id: merchantCode
                },
                amount: {
                    value: amount,
                    unit: 'XOF'
                },
                reference: correlationId
            }),
        });

        const data = await response.json();
        if (response.status === 200) {
            res.json({ paymentResult: data });
        } else {
            res.status(response.status).json({ error: data });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
