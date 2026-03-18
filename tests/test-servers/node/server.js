// Node.js HTTPS test server — exercises OpenSSL dynamic-link capture
'use strict';
const https = require('https');
const crypto = require('crypto');
const { privateEncrypt } = crypto;

// Self-signed cert for test
const { createSign } = crypto;
const forge = require('node-forge');

const pki = forge.pki;
const keys = pki.rsa.generateKeyPair(2048);
const cert = pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
const attrs = [{ name: 'commonName', value: 'localhost' }];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.sign(keys.privateKey);

const options = {
  key:  pki.privateKeyToPem(keys.privateKey),
  cert: pki.certificateToPem(cert),
};

const server = https.createServer(options, (req, res) => {
  const url = req.url || '/';

  if (url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', runtime: 'node' }));
    return;
  }

  if (url.startsWith('/api/')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      method:  req.method,
      path:    url,
      runtime: 'node',
      version: process.version,
    }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(8444, () => {
  console.log('Node HTTPS server on :8444');
});
