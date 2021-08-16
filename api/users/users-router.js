// Require the `restricted` middleware from `auth-middleware.js`
const router = require('express').Router()
const {restricted} = require('../auth/auth-middleware')
const User = require('./users-model')

router.get('/', restricted, async (req, res, next) => {
  try {
    const users = await User.find()
    res.json(users)
  } catch (error) {
    next(error)
  }
})

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;