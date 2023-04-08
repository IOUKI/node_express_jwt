require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())

// 儲存refresh token的地方，可以儲存在緩存或者資料庫
let refreshTokens = [] // 因只是範例，所以使用陣列

// 刷新使用者token
app.post('/token', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if (refreshTokens.includes(refreshToken)) return res.sendStatus(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken})
    })
})

// 移除使用者token
app.delete('/logout', (req, res) => {
    // 清除refreshTokens陣列中的此refreshToken，這樣此refreshToken就不能在被使用
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

// 取得使用者token
app.post('/login', (req, res) => {
    // authentication user

    const username = req.body.username 
    const user = { name: username }

    const accessToken = generateAccessToken(user)
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    res.json({ accessToken: accessToken, refreshToken})
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s'})
}

app.listen(4000)