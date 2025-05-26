const https = require('https');
const crypto = require('crypto');
const url = require('url');

// Function to download PayPal certificate
function downloadCert(certUrl) {
  return new Promise((resolve, reject) => {
    https.get(certUrl, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

// Function to verify PayPal webhook signature
async function verifyPaypalWebhookSignature({
  transmissionId,
  transmissionTime,
  webhookId,
  transmissionSig,
  authAlgo,
  certUrl,
  webhookEventBody, // raw JSON string of webhook payload
}) {
  // Download PayPal certificate
  const cert = await downloadCert(certUrl);

  // Construct the expected signature string
  const expectedSignatureString = `${transmissionId}|${transmissionTime}|${webhookId}|${crypto.createHash('sha256').update(webhookEventBody).digest('hex')}`;

  // Create verifier with auth algorithm
  const verifier = crypto.createVerify(authAlgo);

  verifier.update(expectedSignatureString);
  verifier.end();

  // Verify the signature (transmissionSig is base64)
  const isValid = verifier.verify(cert, transmissionSig, 'base64');

  return isValid;
}

// Example usage with dummy data
(async () => {
  const webhookHeaders = {
    'paypal-transmission-id': '7b1bc3a0-84e9-11ee-a463-8a7cfbc2dd89',
    'paypal-transmission-time': '2025-05-26T08:00:56Z',
    'paypal-cert-url': 'https://api.paypal.com/certs/CERT-123456789',
    'paypal-transmission-sig': 'Base64EncodedSignatureHere==',
    'paypal-auth-algo': 'SHA256withRSA',
  };

  const webhookId = '478032838T250025D'; // your PayPal webhook ID

  // This should be the exact raw JSON string body you received
  const webhookEventBody = JSON.stringify({
    // your webhook payload object here
  });

  try {
    const verified = await verifyPaypalWebhookSignature({
      transmissionId: webhookHeaders['paypal-transmission-id'],
      transmissionTime: webhookHeaders['paypal-transmission-time'],
      webhookId,
      transmissionSig: webhookHeaders['paypal-transmission-sig'],
      authAlgo: webhookHeaders['paypal-auth-algo'],
      certUrl: webhookHeaders['paypal-cert-url'],
      webhookEventBody,
    });

    console.log('Signature verified?', verified);
  } catch (error) {
    console.error('Verification error:', error);
  }
})();
