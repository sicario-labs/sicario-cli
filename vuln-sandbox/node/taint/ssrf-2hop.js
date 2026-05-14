// Taint: SSRF — 2-hop (JS)
// Source: req.body.endpoint → intermediate: fetchData() → Sink: axios.get
// Expected: TruePositive (taint/cwe918)
const express = require('express');
const axios = require('axios');
const app = express();

async function fetchData(endpoint) {
    return axios.get(endpoint);                 // SINK: outbound HTTP request
}

app.post('/fetch', async (req, res) => {
    const endpoint = req.body.endpoint;         // SOURCE: HTTP request body
    const data = await fetchData(endpoint);     // INTERMEDIATE
    res.json(data);
});
