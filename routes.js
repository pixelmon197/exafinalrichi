const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { connection } = require('./db');
const dotenv = require('dotenv');
const { getClientIp } = require('request-ip'); // Para obtener la IP del cliente

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

// =====================================
// ✅ Middleware para verificar token JWT
// =====================================
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Acco denegado. Token no proporcionado.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Token no válido.' });
    }
};

// =====================================
// ✅ LOGIN O CREACIÓN DE USUARIO DESDE LA RUTA /LOGIN
// =====================================
router.post('/login', [
    body('email').isEmail().withMessage('Email inválido'),
    body('password').notEmpty().withMessage('Contraseña requerida')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, nombre, rol } = req.body;

    // Verifica si el usuario ya existe
    connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Error en la consulta:', err);
            return res.status(500).json({ error: 'Error en el servidor' });
        }

        // 🟢 Si el usuario no existe Y se envía nombre y rol, lo crea
        if (results.length === 0 && nombre && rol) {
            console.log('Creando nuevo usuario...');

            const hashedPassword = await bcrypt.hash(password, 10);

            const query = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
            connection.query(query, [nombre, email, hashedPassword, rol], (insertErr, insertResults) => {
                if (insertErr) {
                    console.error('Error al insertar usuario:', insertErr);
                    return res.status(500).json({ error: 'Error al crear usuario' });
                }

                const token = jwt.sign(
                    { id: insertResults.insertId, email },
                    JWT_SECRET,
                    { expiresIn: '1h' }
                );

                // Registrar en la tabla de logs
                const ipAddress = getClientIp(req);
                const logQuery = 'INSERT INTO logs (user_id, action, ip_address) VALUES (?, ?, ?)';
                connection.query(logQuery, [insertResults.insertId, 'Usuario creado', ipAddress], (logErr) => {
                    if (logErr) {
                        console.error('Error al registrar log:', logErr);
                    }
                });

                res.status(201).json({
                    message: 'Usuario creado exitosamente',
                    token
                });
            });

        } else if (results.length > 0) {
            // 🔒 Si el usuario existe, realiza el login normal
            const user = results[0];

            const validPassword = await bcrypt.compare(password, user.password);

            if (!validPassword) {
                return res.status(401).json({ error: 'Contraseña incorrecta' });
            }

            const token = jwt.sign(
                { id: user.id, email: user.email },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            // Registrar en la tabla de logs
            const ipAddress = getClientIp(req);
            const logQuery = 'INSERT INTO logs (user_id, action, ip_address) VALUES (?, ?, ?)';
            connection.query(logQuery, [user.id, 'Inicio de sesión', ipAddress], (logErr) => {
                if (logErr) {
                    console.error('Error al registrar log:', logErr);
                }
            });

            res.json({ message: 'Inicio de sesión exitoso', token });

        } else {
            // 🔴 Si intenta crear usuario pero faltan nombre o rol
            res.status(400).json({ error: 'Faltan campos para crear un nuevo usuario' });
        }
    });
});

// =====================================
// ✅ CRUD DE USUARIOS
// =====================================

// Crear un nuevo usuario
router.post('/users', verifyToken, [
    body('name').notEmpty().withMessage('El nombre es requerido'),
    body('email').isEmail().withMessage('Email inválido'),
    body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres'),
    body('role').notEmpty().withMessage('El rol es requerido')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password, role } = req.body;

    // Verificar si ya existe el usuario
    connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Error en la base de datos' });
        }

        if (results.length > 0) {
            return res.status(400).json({ error: 'El usuario ya existe' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';

        connection.query(query, [name, email, hashedPassword, role], (insertErr, insertResults) => {
            if (insertErr) {
                return res.status(500).json({ error: 'Error al crear usuario' });
            }

            res.status(201).json({ message: 'Usuario creado exitosamente', userId: insertResults.insertId });
        });
    });
});

// Obtener todos los usuarios (con paginación)
router.get('/users', verifyToken, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    connection.query(
        'SELECT * FROM users LIMIT ? OFFSET ?',
        [limit, offset],
        (err, results) => {
            if (err) {
                console.error('Error:', err);
                return res.status(500).json({ error: 'Error al obtener usuarios' });
            }

            res.json({ page, limit, data: results });
        }
    );
});

// Obtener un usuario por ID
router.get('/users/:id', verifyToken, (req, res) => {
    const id = req.params.id;

    connection.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Error en la consulta' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.json(results[0]);
    });
});

// Actualizar usuario
router.put('/users/:id', verifyToken, (req, res) => {
    const id = req.params.id;
    const { name, email, role } = req.body;

    const query = 'UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?';
    connection.query(query, [name, email, role, id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Error al actualizar usuario' });
        }

        res.json({ message: 'Usuario actualizado exitosamente' });
    });
});

// Eliminar usuario
router.delete('/users/:id', verifyToken, (req, res) => {
    const id = req.params.id;

    connection.query('DELETE FROM users WHERE id = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Error al eliminar usuario' });
        }

        res.json({ message: 'Usuario eliminado correctamente' });
    });
});

// =====================================
// ✅ GESTIÓN DE SESIONES (CREAR SESIONES)
// =====================================
router.post('/sessions', verifyToken, (req, res) => {
    const { token } = req.body;
    const userId = req.user.id;
    const expiresAt = new Date(Date.now() + 3600 * 1000); // Expira en 1 hora

    // Crear una nueva sesión
    const query = 'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)';
    connection.query(query, [userId, token, expiresAt], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Error al crear la sesión' });
        }

        res.status(201).json({ message: 'Sesión creada exitosamente' });
    });
});

module.exports = router;
