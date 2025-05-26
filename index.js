const https = require('https');
const crypto = require('crypto');
const http = require('http');

/**
 * Download PayPal certificate from certUrl (returns PEM string)
 * @param {string} certUrl - HTTPS URL to PayPal's cert
 * @returns {Promise<string>} PEM certificate string
 */
function downloadCert(certUrl) {
  return new Promise((resolve, reject) => {
    const options = {
      headers: {
        'User-Agent': 'Node.js PayPal Webhook Verifier',
        'Accept': 'application/pem-certificate-chain',
      },
    };

    https.get(certUrl, options, (res) => {
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to get cert: ${res.statusCode}`));
      }

      let data = '';
      res.on('data', (chunk) => (data += chunk));
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
  // Download the certificate
  const cert = await downloadCert(certUrl);

  // Construct the expected signature string exactly per PayPal spec:
  // transmissionId|transmissionTime|webhookId|SHA256(webhookEventBody)
  const expectedSignatureString = [
    transmissionId,
    transmissionTime,
    webhookId,
    crypto.createHash('sha256').update(webhookEventBody).digest('hex'),
  ].join('|');

  // Use Node.js crypto algorithm name for PayPal's SHA256withRSA
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(expectedSignatureString);
  verifier.end();

  // Verify the signature (transmissionSig is base64)
  return verifier.verify(cert, transmissionSig, 'base64');
}

// Create an HTTP server to listen for webhook events
const PORT = process.env.PORT || 3000;

const server = http.createServer(async (req, res) => {
  if (req.method !== 'POST' || req.url !== '/webhook') {
    res.writeHead(404);
    return res.end('Not Found');
  }

  // Collect the raw body data as a string
  let rawBody = '';
  req.on('data', (chunk) => {
    rawBody += chunk;
  });

  req.on('end', async () => {
    try {
      // Extract PayPal headers
      const headers = req.headers;
      const transmissionId = headers['paypal-transmission-id'];
      const transmissionTime = headers['paypal-transmission-time'];
      const certUrl = headers['paypal-cert-url'];
      const transmissionSig = headers['paypal-transmission-sig'];
      const authAlgo = headers['paypal-auth-algo'];

      // Your PayPal webhook ID (replace with your actual webhook ID)
      const webhookId = '478032838T250025D';

      if (!transmissionId || !transmissionTime || !certUrl || !transmissionSig || !authAlgo) {
        res.writeHead(400);
        return res.end('Missing required PayPal headers');
      }

      // Verify signature
      const verified = await verifyPaypalWebhookSignature({
        transmissionId,
        transmissionTime,
        webhookId,
        transmissionSig,
        authAlgo,
        certUrl,
        webhookEventBody: rawBody,
      });

      if (verified) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'verified' }));
      } else {
        res.writeHead(400);
        res.end('Signature verification failed');
      }
    } catch (error) {
      console.error('Verification error:', error);
      res.writeHead(500);
      res.end('Internal Server Error');
    }
  });
});

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Send PayPal webhook POST requests to http://localhost:${PORT}/webhook`);
});
