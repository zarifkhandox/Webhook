const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
require('dotenv').config(); 

const app = express();
const dbPath = process.env.DB_PATH || 'keys.db'; 
const db = new sqlite3.Database(dbPath);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


app.use(express.static(path.join(__dirname, 'public')));


db.serialize(() => {
    db.run(`DROP TABLE IF EXISTS keys`);
    db.run(`CREATE TABLE keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_url TEXT,
        encrypted_webhook TEXT,
        iv TEXT,
        key TEXT
    )`);
});

app.post('/encrypt', (req, res) => {
    const { webhook_url } = req.body;
    if (!webhook_url) {
        console.error('Webhook URL is missing');
        return res.status(400).json({ error: 'Webhook URL is required' });
    }

    try {
        const iv = crypto.randomBytes(16);
        const key = crypto.randomBytes(32);

        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(webhook_url, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const apiUrl = `/${crypto.randomBytes(15).toString('hex')}`;

        db.run(`INSERT INTO keys (api_url, encrypted_webhook, iv, key) VALUES (?, ?, ?, ?)`, [apiUrl, encrypted, iv.toString('hex'), key.toString('hex')], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to store the encrypted webhook' });
            }
            const generationApiPort = process.env.GENERATION_API_PORT || PORT;
            res.json({ encrypted_webhook: encrypted, api_url: `http://www.hosted-api.42web.io:${generationApiPort}${apiUrl}` });
        });
    } catch (error) {
        console.error('Encryption error:', error);
        res.status(500).json({ error: 'Encryption failed' });
    }
});

const PORT = process.env.SERVER_PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
