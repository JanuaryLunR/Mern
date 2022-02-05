const {} = require('express')
const bcrypt = require('bcryptjs')
const config = require('config')
const jsonwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

// /api/auth/register
router.post(
  '/register',
  [
    check('email', 'Uncorrect email').isEmail(),
    check('password', 'Too short password').isLength({ min: 6 })
  ],
   async (req, res) => {
  try {
    const errors = validationResult(req)

    if (error.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Incorrect register data'
      })
    }

    const {email, password} = req.body

    const candidate = await User.findOne({ email: email})

    if (candidate) {
      return res.status(400).json({ message: 'User with this email already exists'})
    }

    const hashedPassword = await bcrypt.hash(password, 12)
    const user = new User({ email, password: hashedPassword })

    await user.save()

    res.status(201).json({ message: 'User created'})


  } catch (e) {
    res.status(500).json({ message: 'Something goes wrong'})
  }
})

// /api/auth/login
router.post(
  '/login', 
  [
    check('email', 'Use correct email').normalizeEmail().isEmail(),
    check('password', 'Enter your password').exists()
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req)

    if (error.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Incorrect data'
      })
    }

    const {email, password} = req.body

    const user = await User.findOne({ email: email })

    if (!user) {
      return res.status(400).json({ message: 'User not found' })
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.status(400).json({ message: 'Uncorrect password'})
    }

    const token = jsonwt.sign(
      { userId: user.id },
      config.get('jsonwtSecret'),
      { expiresIn: '1h' }
    )

    res.json({ token, userId: user.id})


  } catch (e) {
    res.status(500).json({ message: 'Something goes wrong'})
  }
})

module.exports = router