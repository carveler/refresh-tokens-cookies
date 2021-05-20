const express = require('express');
const app = express();
const cors = require("cors")
const cookieParser = require("cookie-parser")
const jwt = require("jsonwebtoken")

// ALLOW that cookies are sent to us
app.use( cors({ origin: 'http://localhost:3000', credentials: true }) )
app.use( cookieParser() )
app.use( express.json() )

app.get('/', (req, res) => {
  res.send('Hello World!');
});

// const JWT_TOKEN = { key: 'token', secret: "holy_secret", expiry: 1000*60*2 }
// const JWT_REFRESH = { key: 'refresh_token', secret: "holy_refresh_secret", expiry: 1000*60*4 }
const JWT_TOKEN = { key: 'token', secret: "holy_secret", expiry: '1m' }
const JWT_REFRESH = { key: 'refresh_token', secret: "holy_refresh_secret", expiry: '2m' }
const COOKIE_BASE_CONFIG = { httpOnly: true, maxAge: 1000*60*10 }

app.get('/logout', (req, res, next) => {
  res.clearCookie(JWT_TOKEN.key)
  res.clearCookie(JWT_REFRESH.key)
  res.json({ message: "Logged out successfully" })
})

const generateTokenPair = (user, res) => {
  // create a "visitor card" (= so we will recognise you the next time!)
  const token = jwt.sign(
    { _id: user._id }, JWT_TOKEN.secret, { expiresIn: JWT_TOKEN.expiry } 
  )
  const refreshToken = jwt.sign(
    { _id: user._id }, JWT_REFRESH.secret, { expiresIn: JWT_REFRESH.expiry } 
  )

  // pin the visitor card to your dress (=attach cookie)
  res.cookie(JWT_TOKEN.key, token, COOKIE_BASE_CONFIG)
  res.cookie(JWT_REFRESH.key, refreshToken, COOKIE_BASE_CONFIG)

  return { token, refreshToken }
}

app.get('/login', (req, res, next) => {

  let userFound = {
    _id: '12345',
    username: 'losrobbos',
    email: 'losrobbos@backend.com'
  }

  console.log("Login successful")

  const { token, refreshToken } = generateTokenPair(userFound, res)

  res.json({
    user: userFound,
    token: token,
    refresh_token: refreshToken
  })

})

// SECURITY GUARD
  // that guy here will check if we provide a valid visitor card before granting acccess...
const auth = (req, res, next) => {

  // VISITOR CARD CHECK...
  if(!req.cookies.token) {
    console.log("No token provided")
    let error = new Error("No token provided")
    error.status = 401 // Unauthorized
    return next(error)
  }

  try {
    const tokenContent = jwt.verify(req.cookies[JWT_TOKEN.key], JWT_TOKEN.secret)
    req.user = tokenContent
    console.log("Valid Token received. Data:", req.user)
    next()
  }
  catch(err) {
    // console.log("Expired?", err.expiredAt)

    // auth token malformed / not expired? -> reject call
    if(!err.expiredAt) {
      console.log("TOKEN malformed...")
      return next(err)
    }
    // check refresh token...
    try {
      console.log("TOKEN expired. Checking refresh token...")
      const refreshContent = jwt.verify(req.cookies[JWT_REFRESH.key], JWT_REFRESH.secret)
      console.log("Refresh token: ", refreshContent)
      generateTokenPair(refreshContent, res)
      console.log("Generated new pair of tokens")
      next()
    }
    // refresh token either invalid or expired -> reject & clear all auth cookies
    catch(err) {
      console.log("REFRESH TOKEN expired. Logging out + clearing cookies...")
      res.clearCookie( JWT_TOKEN.key )
      res.clearCookie( JWT_REFRESH.key )
      next(err)
    }
  }

}

// protected resource
app.get('/protected', auth, (req, res, next) => {

  res.json({
    message: 'You are allowed to pass! Enjoy the flight!',
    cookies: req.cookies
  })

})

// final error handler
app.use((err, req, res, next) => {
  console.log(err.message)
  res.status(err.status || 500).json({ error: { message: err.message || err }})
})

app.listen(5000, () => {
  console.log('Example app listening on port 5000!');
});

//Run app, then load http://localhost:5000 in a browser to see the output.