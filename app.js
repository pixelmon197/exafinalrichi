require('dotenv').config();
const cors = require('cors');   
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const routes = require('./routes');

app.use(bodyParser.json());
app.use(cors());

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

app.use('/api', routes);

const PORT = process.env.PORT || 3007;
app.listen(PORT, () => {
    console.log(`Servidor API a la espera de consulta, por el puerto ${PORT}`);
});