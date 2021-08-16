// require auth middleware, router, bcrypt, user
const router = require('express').Router()
const bycrypt = require('bcryptjs')
const User = require('../users/users-model');
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
} = require('./auth-middleware')


router.post('/register', checkPasswordLength, checkUsernameFree, (req, res, next) => {
  const {username, password} = req.body
  const hash =  bycrypt.hashSync(password, 8)
  User.add({username, password: hash}) // store hash not plain-text pass
    .then(saved => {
      res.status(201).json(saved)
    })
    .catch(next)
})

  router.post('/login', checkUsernameExists, (req, res, next) => {
    const {password} = req.body
    if (bycrypt.compareSync(password, req.user.password)) {
      // cookie set on client, server stores session with sid
      req.session.user = req.user
      res.json({message: `Welcome ${req.user.username}!`})
    } else {
      next({status: 401, message: 'Invalid credentials'})
    }
  })

  router.get('/logout', (req, res, next) => {
    if (req.session.user) {
      req.session.destroy(err => {
        if (err) {
          next(err)
        } else {
          res.json({message: 'logged out'})
        }
      })
    } else {
      res.json({message: 'no session'})
    }
  })
 
// 💡 EXPORT router
module.exports = router;