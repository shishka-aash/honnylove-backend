const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const cartRoutes = require('./routes/cartRoutes');
const userRoutes = require('./routes/userRoutes');
const productRoutes = require('./routes/productRoutes');
const pool = require('./config/database');

const app = express();
const PORT = process.env.PORT || 9999;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/cart', cartRoutes);

app.use('/api/products', productRoutes);

app.use('/api/user', userRoutes);
// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Маршрут не найден',
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на порту ${PORT}`);
    console.log(`📊 База данных: ${process.env.DB_NAME}`);
});
