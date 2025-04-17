const crypto = require('crypto');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // 32 bytes key
const IV = process.env.ENCRYPTION_IV; // 16 bytes IV

// Encrypts a JWT token
const encrypt = (payload) => {
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return encrypted;
};

// Decrypts and verifies the JWT token
const decrypt = (encryptedToken) => {
  const decipher = crypto.createDeipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  const decoded = jwt.verify(decrypted, process.env.JWT_SECRET);
  return decoded;
};

module.exports = {
  encrypt,
  decrypt
};
