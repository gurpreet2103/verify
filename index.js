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
        // Removed strict Accept header to avoid 406 error
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

  // Digest algorithm - use sha256 regardless of authAlgo string (PayPal uses SHA256withRSA)
  const digestAlgorithm = 'sha256';

  // Construct the signature string: transmissionId|transmissionTime|webhookId|SHA256(webhookEventBody)
  const expectedSignatureString = [
    transmissionId,
    transmissionTime,
    webhookId,
    crypto.createHash(digestAlgorithm).update(webhookEventBody).digest('hex'),
  ].join('|');

  // Create verifier
  const verifier = crypto.createVerify(digestAlgorithm);
  verifier.update(expectedSignatureString);
  verifier.end();

  // Verify signature (transmissionSig is base64)
  return verifier.verify(cert, transmissionSig, 'base64');
}

// HTTP server to receive PayPal webhook POSTs
const PORT = process.env.PORT || 3000;

const server = http.createServer(async (req, res) => {
  if (req.method !== 'POST' || req.url !== '/webhook') {
    res.writeHead(404);
    return res.end('Not Found');
  }

  // Collect raw request body
  let rawBody = '';
  req.on('data', (chunk) => {
    rawBody += chunk;
  });

  req.on('end', async () => {
    try {
      const headers = req.headers;

      const transmissionId = headers['paypal-transmission-id'];
      const transmissionTime = headers['paypal-transmission-time'];
      const certUrl = headers['paypal-cert-url'];
      const transmissionSig = headers['paypal-transmission-sig'];
      const authAlgo = headers['paypal-auth-algo'];

      // Your webhook ID from PayPal Developer Dashboard
      const webhookId = '478032838T250025D';

      if (!transmissionId || !transmissionTime || !certUrl || !transmissionSig || !authAlgo) {
        res.writeHead(400);
        return res.end('Missing required PayPal headers');
      }

      // Verify the signature
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
