console.log("oi gente")
// Imports
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const port = process.env.PORT || 3000;
const DB_USERNAME = process.env.DB_USERNAME;
const DB_PASSWORD = process.env.DB_PASSWORD;
const app = express();

// Models
const User = require('./models/user');


// Config JSON middleware
app.use(express.json());

// Routes

// Public route'
app.get('/', (req, res)=>{
    res.status(200).json({message:"Bem vindo a nossa API"});
})

// Private route
app.get('/user/:id', checkToken, async (req, res)=>{ //O nosso middleware checkToken é passado como segundo parâmetro da função get ou de outras funções que necessitem verificar o token
    const id = req.params.id;

    const user = await User.findById(id, '-password'); //Passando a strig '-password' como segundo parametro eu consigo filtrar, fazendo com que todos os dados do usuário sejam retornados, com excessão da senha.

    if (!user){
        return res.status(404).json({message: "User not found"});
    }

    try{
        res.status(200).json({user});
    }catch(error){
        console.log({error: error});
        res.status(500).json({message: "Internal server error"});
    }
})


function checkToken(req, res, next){
    const authHeader = req.headers['authorization']; //Pagando o 'Bearer + token'
    const token = authHeader && authHeader.split(" ")[1]; //O primeiro authHeader dessa linha verifica se existe a string //Depois do delimitador espaço, pegar 0 restante da string
    // Validar se o token existe
    if(!token){
        return res.status(401).json({message: "Acesso negado"}); //Código 401 é para acesso negado
    }

    // Se houver um token, validar se o token é válido
    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret); //Caso o token seja inválido, o try falha e cai no catch de token inválido
        next(); //Se o token for válido, libera o acesso a rota
    } catch (error) {
        console.log({error: error});
        res.status(400).json({message: "Token inválido"});
    }

}
// User register
app.post('/auth/register', async(req, res)=>{
    const{name, email, password, confirmPassword} = req.body;
    
    // validations
    if(!name){
        return res.status(422).json({message: "The name field is required"});
    }
    if(!email){
        return res.status(422).json({message: "The email field is required"});
    }
    if(!password){
        return res.status(422).json({message: "The password field is required"});
    }
    if(!confirmPassword){
        return res.status(422).json({message: "The confirmPassword field is required"});
    }
    if(password !== confirmPassword){
        return res.status(422).json({message: "Password do not match"});
    }


    // Check if user already exists
    const userExists = await User.findOne({email: email}); //É como se fosse uma query where em MySQL

    if(userExists){
        return res.status(422).json({message: "Email already registered, try another email."});
    }

    const salt = await bcrypt.genSalt(12); //Adiciona caracteres à senha informada pelo usuário para dificultar a vida dos hackers
    const passwordHash = await bcrypt.hash(password, salt); //Aplica uma hash function na senha junto com o salt
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save();  //persiste o usuário no banco de dados
        res
            .status(201) //código quando algo é criado no banco
            .json({message: "User created sucessfully"})
    } catch (error) {
        console.log(error); //Não é uma boa prática retornar o error na response, por isso retornei uma mensagem genérica e apenas logei o error
        res
            .status(500)
            .json({msgError: "Server error"});
    }
    
})

// Login Route
app.post("/auth/login", async(req, res)=>{
    const {email, password} = req.body;
    if(!email){
        return res.status(422).json({message: "The email is required"});
    }
    if(!password){
        return res.status(422).json({message: "The password is required"});
    }
    const user = await User.findOne({email: email});
    if(!user){
        return res.status(404).json({message: "User do not exists"}); //Here I used code 404, that means resource not found
    }

    //Checking if the password is right
    const checkPassword = await bcrypt.compare(password, user.password); 
    if(!checkPassword){
        return res.status(422).json({message: "Password do not match"});
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id
            },
            secret
        );

        res
            .status(200)
            .json({
                message: "User authenticated successfully",
                token
            });
        
    } catch (error) {
        console.log(error);
        res
            .status(500)
            .json({message: "Server Error"});
    }
})
mongoose.connect(`mongodb+srv://${DB_USERNAME}:${DB_PASSWORD}@jwt-auth.bxwie.mongodb.net/jwt-auth?retryWrites=true&w=majority`)
.then(()=>{
    app.listen(port, ()=>{
        console.info(`Application running on port ${port}`);
    });
    console.log("MongoDB Connected :)");
})
.catch((err)=>{
    console.log(err);
})
// Provide