const User = require('../models/User');
const express = require('express');
const router = express.Router();

router.post('/register', async (req, res) => {
  const userData = req.body;
  try {
    const userExists = await User.findOne({ email: userData.email });
    if (userExists) {
      return res.status(400).json({ errors: ['User already exists'] });
    }
    const user = await User.create(userData);
    res.status(201).json(user);
    console.log('User created successfully');
  } catch (error) {
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map(
        (err) => err.message
      );
      res.status(400).json({ errors: validationErrors });
    } else {
      res.status(500).json(error);
    }
  }
});

module.exports = router;
