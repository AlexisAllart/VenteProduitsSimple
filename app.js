// express
let express=require('express');
let app=express();

// body-parser
let bodyParser = require('body-parser');
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: false}));

let user = require('./routes/user');
let role = require('./routes/role');
let produit = require('./routes/produit');

app.use("/user", user);
app.use("/role", role);
app.use("/produit", produit);

app.listen(9090);