import express from 'express';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import cors from 'cors';
import axios from 'axios';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3005;

app.get('/api/virustotal/:domain', async (req, res) => {
  const domain = req.params.domain;
  const url = `https://www.virustotal.com/api/v3/domains/${domain}`;

  try {
    const response = await fetch(url, {
      headers: { 'x-apikey': process.env.VT_API_KEY }
    });
    
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('VirusTotal Error:', err);
    res.status(500).json({ error: 'VT API Failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
