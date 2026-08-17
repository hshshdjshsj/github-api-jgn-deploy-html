'use strict';

const fs = require('fs');
const crypto = require('crypto');

const targetFile = String(
  process.env.DIRAC_ATTEST_TARGET_FILE || ''
).trim();

const reportFile = String(
  process.env.DIRAC_ATTEST_CI_REPORT || ''
).trim();

const privateKeyPem = String(
  process.env.DIRAC_BACKEND_ATTESTATION_PRIVATE_KEY_PEM || ''
);

if (!targetFile || !reportFile || !privateKeyPem) {
  throw new Error('DIRAC_ATTEST_INPUT_INVALID');
}

if (!fs.existsSync(targetFile)) {
  throw new Error('DIRAC_ATTEST_TARGET_FILE_NOT_FOUND');
}

if (!fs.existsSync(reportFile)) {
  throw new Error('DIRAC_ATTEST_CI_REPORT_NOT_FOUND');
}

const report = JSON.parse(
  fs.readFileSync(reportFile, 'utf8')
);

const requiredPass = [
  'syntax_test',
  'unit_security_tests',
  'adversarial_10000',
  'replay_cross_instance',
  'concurrency_race',
  'ssrf',
  'dns_rebinding',
  'request_smuggling',
  'sast',
  'sca',
  'secret_scan',
  'artifact_hash'
];

if (
  Number(report.tests_passed) < 10000 ||
  Number(report.tests_failed) !== 0 ||
  Number(report.critical_open) !== 0 ||
  Number(report.high_open) !== 0 ||
  requiredPass.some(
    (key) => String(report[key] || '') !== 'PASS'
  )
) {
  throw new Error('DIRAC_ATTEST_CI_REPORT_NOT_PASSING');
}

const evidenceHash = String(
  report.evidence_sha256 || ''
).toLowerCase();

if (!/^[a-f0-9]{64}$/.test(evidenceHash)) {
  throw new Error('DIRAC_ATTEST_EVIDENCE_HASH_INVALID');
}

const privateKey = crypto.createPrivateKey(
  privateKeyPem
);

if (privateKey.asymmetricKeyType !== 'ed25519') {
  throw new Error(
    'DIRAC_ATTEST_PRIVATE_KEY_MUST_BE_ED25519'
  );
}

const publicKey = crypto.createPublicKey(
  privateKey
);

const publicKeyDer = publicKey.export({
  type: 'spki',
  format: 'der'
});

const targetBuffer = fs.readFileSync(targetFile);

const buildSha256 = crypto
  .createHash('sha256')
  .update(targetBuffer)
  .digest('hex');

const testedAt = new Date();

const expiresAt = new Date(
  testedAt.getTime() + 168 * 60 * 60 * 1000
);

const payload = {
  attestation_type:
    'dirac-backend-security-attestation-v230',

  attestation_key_sha256: crypto
    .createHash('sha256')
    .update(publicKeyDer)
    .digest('hex'),

  build_sha256: buildSha256,
  node_version: process.version,

  owasp_profile:
    'OWASP-TOP-10-2025-BACKEND',

  asvs_profile:
    'OWASP-ASVS-5.0-L2-BACKEND',

  owasp_backend_gate: 'PASS',

  tests_passed: Number(report.tests_passed),
  tests_failed: Number(report.tests_failed),
  critical_open: Number(report.critical_open),
  high_open: Number(report.high_open),

  ...Object.fromEntries(
    requiredPass.map((key) => [key, 'PASS'])
  ),

  evidence_sha256: evidenceHash,
  tested_at: testedAt.toISOString(),
  expires_at: expiresAt.toISOString()
};

const encoded = Buffer
  .from(JSON.stringify(payload), 'utf8')
  .toString('base64url');

const signature = crypto
  .sign(
    null,
    Buffer.from(encoded, 'utf8'),
    privateKey
  )
  .toString('base64url');

const output = {
  payload,
  encoded,
  signature,

  public_key_pem: publicKey.export({
    type: 'spki',
    format: 'pem'
  })
};

fs.writeFileSync(
  'attestation-output.json',
  JSON.stringify(output, null, 2)
);

console.log('Attestation berhasil dibuat.');
console.log('Build SHA-256:', buildSha256);
console.log('Node version:', process.version);
