const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASSWORD,
    database: process.env.DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

// Проверка подключения
async function testConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Успешное подключение к MySQL');
        connection.release();
    } catch (error) {
        console.error('❌ Ошибка подключения к MySQL:', error);
    }
}

testConnection();

module.exports = pool;
