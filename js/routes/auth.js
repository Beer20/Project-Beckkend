// routes/auth.js
const express = require('express');
const router = express.Router();
const User = require('../models'); // Memastikan model User diambil dari index.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Rute pendaftaran
router.post('/register', async (req, res, next) => {
    try {
        const { username, password, role, profilePic } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10); // Mengenkripsi password sebelum menyimpannya
        const newUser = await User.create({ username, password: hashedPassword, role, profilePic });
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        next(err);
    }
});

// Rute login
router.post('/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ where: { username } });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign(
            { id: user.id, role: user.role },
            'your_jwt_secret', 
            { expiresIn: '1h' }
        );
        res.json({ token });
    } catch (err) {
        next(err);
    }
});

module.exports = router;
