const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Servir les fichiers statiques depuis la racine du projet
app.use(express.static(__dirname));

const ACCESS_ID = '4wnuc99jvqcrv9hhkgpw';
const ACCESS_SECRET = '9046b8a58f3240dc961b779bb2da13f3';
const API_BASE = 'https://openapi.tuyaeu.com';

let accessToken = null;
let tokenExpiry = 0;

// Fonction pour créer la signature
function createSign(clientId, secret, t, accessToken = '') {
  const str = clientId + accessToken + t;
  const hash = crypto.createHmac('sha256', secret)
    .update(str, 'utf8')
    .digest('hex');
  return hash.toUpperCase();
}

// Obtenir le token
async function getAccessToken() {
  if (accessToken && Date.now() < tokenExpiry) {
    return accessToken;
  }

  const t = Date.now().toString();
  const sign = createSign(ACCESS_ID, ACCESS_SECRET, t);

  const response = await axios.get(`${API_BASE}/v1.0/token?grant_type=1`, {
    headers: {
      'client_id': ACCESS_ID,
      'sign': sign,
      'sign_method': 'HMAC-SHA256',
      't': t
    }
  });

  if (response.data.success) {
    accessToken = response.data.result.access_token;
    tokenExpiry = Date.now() + (response.data.result.expire_time * 1000);
    return accessToken;
  }
  throw new Error('Failed to get access token');
}

// Route pour la page d'accueil (index.html à la racine)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// API pour lister les appareils
app.get('/api/devices', async (req, res) => {
  try {
    const token = await getAccessToken();
    const t = Date.now().toString();
    const sign = createSign(ACCESS_ID, ACCESS_SECRET, t, token);

    const response = await axios.get(`${API_BASE}/v1.0/devices`, {
      headers: {
        'client_id': ACCESS_ID,
        'access_token': token,
        'sign': sign,
        'sign_method': 'HMAC-SHA256',
        't': t
      }
    });

    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API pour contrôler un appareil
app.post('/api/devices/:deviceId/commands', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { commands } = req.body;
    const token = await getAccessToken();
    const t = Date.now().toString();

    const body = JSON.stringify({ commands });
    const contentHash = crypto.createHash('sha256')
      .update(body)
      .digest('hex');

    const stringToSign = [
      ACCESS_ID,
      token,
      t,
      'POST',
      contentHash,
      '',
      `/v1.0/devices/${deviceId}/commands`
    ].join('');

    const sign = crypto.createHmac('sha256', ACCESS_SECRET)
      .update(stringToSign, 'utf8')
      .digest('hex')
      .toUpperCase();

    const response = await axios.post(
      `${API_BASE}/v1.0/devices/${deviceId}/commands`,
      { commands },
      {
        headers: {
          'client_id': ACCESS_ID,
          'access_token': token,
          'sign': sign,
          'sign_method': 'HMAC-SHA256',
          't': t,
          'Content-Type': 'application/json'
        }
      }
    );

    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur lancé sur le port ${PORT}`);
});
