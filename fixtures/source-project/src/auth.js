const crypto = require('node:crypto');
const https = require('node:https');

// Planted issue SP-2: hardcoded credential (A07, CWE-798)
const API_SECRET = 'sk-live-a1b2c3d4e5f6g7h8i9j0k1l2m3n4';

// Planted issue SP-3: weak hash for password storage (A04, CWE-327)
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Planted issue SP-4: TLS certificate verification disabled (A04, CWE-295)
function fetchBilling(invoiceId) {
  return fetch(`https://billing.internal.example/invoices/${invoiceId}`, {
    agent: new https.Agent({ rejectUnauthorized: false }),
  });
}

module.exports = { API_SECRET, hashPassword, fetchBilling };
