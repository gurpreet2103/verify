const https = require('https');
const crypto = require('crypto');

// Download PayPal certificate from certUrl (returns PEM string)
function downloadCert(certUrl) {
  return new Promise((resolve, reject) => {
    https.get(certUrl, (res) => {
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to get cert: ${res.statusCode}`));
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

/**
 * Verify PayPal webhook signature.
 * 
 * @param {Object} params
 * @param {string} params.transmissionId - PayPal transmission ID header
 * @param {string} params.transmissionTime - PayPal transmission time header
 * @param {string} params.webhookId - Your webhook ID (from PayPal dashboard)
 * @param {string} params.transmissionSig - PayPal transmission signature (base64)
 * @param {string} params.authAlgo - PayPal auth algorithm (e.g. "SHA256withRSA")
 * @param {string} params.certUrl - PayPal certificate URL (starts with https://)
 * @param {string} params.webhookEventBody - Raw JSON string body of webhook event
 * 
 * @returns {Promise<boolean>} true if verified, false if not
 */
async function verifyPaypalWebhookSignature({
  transmissionId,
  transmissionTime,
  webhookId,
  transmissionSig,
  authAlgo,
  certUrl,
  webhookEventBody,
}) {
  // Download cert
  const cert = await downloadCert(certUrl);

  // Use 'sha256' digest for Node.js crypto regardless of authAlgo string
  const digestAlgorithm = 'sha256';

  // Construct expected signature string exactly per PayPal spec:
  // transmissionId|transmissionTime|webhookId|SHA256(webhookEventBody)
  const expectedSignatureString = [
    transmissionId,
    transmissionTime,
    webhookId,
    crypto.createHash(digestAlgorithm).update(webhookEventBody).digest('hex'),
  ].join('|');

  // Create verifier with the digest algorithm
  const verifier = crypto.createVerify(digestAlgorithm);

  verifier.update(expectedSignatureString);
  verifier.end();

  // Verify the signature (transmissionSig is base64)
  const isValid = verifier.verify(cert, transmissionSig, 'base64');

  return isValid;
}

// Example usage:
(async () => {
  const webhookHeaders = {
    'paypal-transmission-id': '7b1bc3a0-84e9-11ee-a463-8a7cfbc2dd89',
    'paypal-transmission-time': '2025-05-26T08:00:56Z',
    'paypal-cert-url': 'https://api.paypal.com/certs/CERT-123456789',
    'paypal-transmission-sig': 'Base64EncodedSignatureHere==',
    'paypal-auth-algo': 'SHA256withRSA',
  };

  const webhookId = '478032838T250025D'; // Your PayPal webhook ID

  // This should be the exact raw JSON string body you received from PayPal webhook
  const webhookEventBody = JSON.stringify({
    // ... your webhook payload here
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
