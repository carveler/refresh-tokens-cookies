// const JWT_TOKEN = { key: 'token', secret: "holy_secret", expiry: 1000*60*2 }
// const JWT_REFRESH = { key: 'refresh_token', secret: "holy_refresh_secret", expiry: 1000*60*4 }
const JWT_TOKEN = { key: 'token', secret: "holy_secret", expiry: '1m' }
const JWT_REFRESH = { key: 'refresh_token', secret: "holy_refresh_secret", expiry: '2m' }
const COOKIE_BASE_CONFIG = { httpOnly: true, maxAge: 1000*60*10 }

/**
 * Generate a pair of ACCESS TOKEN + REFRESH TOKEN
 * => access token - short lived token for accessing protected data
 * => refresh token - long lived token for refreshing an ACTIVE session
 * 
 * A refresh token allows people to stay logged in when still being ACTIVE in the app
 * (so when "clicking around")
 *
 * For people NOT being active in the app anymore, their session will expire once
 * their auth token + refresh token expired 
 * (for security reasons, so an attacker has not much time sniffing the refresh token)
 */
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

module.exports = {
  JWT_TOKEN,
  JWT_REFRESH,
  COOKIE_BASE_CONFIG,
  generateTokenPair 
}