// Simple static server for attacker site (http://localhost:4000)
const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 4000;
app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log(`Attacker site at http://localhost:${PORT}`));
