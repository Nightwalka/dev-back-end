const express = require('express')
const app = express()
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = WAL")

//db set up start





//db set up end


app.set("view engine", "ejs")
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(function(req,res,next){
    res.locals.errors = []
    next()
})


app.get('/', (req,res) =>{
    res.render("homepage")
})

app.get("/login", (req,res) =>{
    res.render("login")
})


app.post("/register", (req,res) =>{
    const errors =[]
    if (typeof req.body.username !== "string") req.body.username= ""
    if (typeof req.body.password !== "string") req.body.password= ""

    req.body.username = req.body.username.trim()

    if (!req.body.username) errors.push("You must provide a user name ")
    if (req.body.username && req.body.username.length < 3) errors.push("A username should be more than three characters ")
    if (req.body.username && req.body.username.length > 10) errors.push("A username should not more than 10 characters ")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("A username can a only contain letters and numbers ")
    
    if (!req.body.password) errors.push("You must provide a user name ")
    if (req.body.password && req.body.password.length < 8) errors.push("A password should be more than three characters ")
    if (req.body.password && req.body.password.length > 15) errors.push("A password should not more than 10 characters ")

    if (errors.length){
        return res.render('homepage', {errors})
    
        
    }
    //save the new user to the Db and log in the user by giving them the session cookie
})
app.listen(3000)