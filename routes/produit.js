let express = require('express');
let router = express.Router();
let db = require(`../models/index.js`);

// jsonwebtoken
const jwt = require('jsonwebtoken');
const checkToken = (req, res, next) => {
    const header = req.headers['authorization'];
    if(typeof header !== 'undefined') {
        const bearer = header.split(' ');
        const token = bearer[1];
        req.token = token;
        next();
    }
    else {
        res.sendStatus(403);
    }
};

// multer
let multer = require('multer');
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})
const upload = multer({storage: storage})

// BEGIN LIST (PUBLIC/NOT PROTECTED)
router.get('/list',(req,res)=>{
    db.Produit.findAll({})
    .then(produits=>{
        res.setHeader('Content-type','application/json ; charset=utf-8');
        res.json(produits);
        res.status(200);
        res.end();
    })
    .catch(error=>{
        res.setHeader('Content-type','application/json ; charset=utf-8');
        res.json(error);
        res.status(400).send('400 Error');
        res.end();
    });
});
// END LIST (PUBLIC/NOT PROTECTED)

// BEGIN SHOW DETAILS (PUBLIC)
router.get('/details/:id', (req, res) => {
        db.Produit.findOne({
            where:{
                'id': req.params.id
            }
        })
        .then(produit=>{
            res.setHeader('Content-type','application/json ; charset=utf-8');
            res.json(produit);
            res.status(200);
            res.end();
        })
        .catch(error=>{
            res.setHeader('Content-type','application/json ; charset=utf-8');
            res.json(error);
            res.status(400).send('400 Error');
            res.end();
        });
});
// END SHOW DETAILS (PUBLIC)

// BEGIN CREATE NEW PRODUIT (PROTECTED BY ROLE_ID (1=ADMIN))
router.post('/create', checkToken, (req, res) => {
    jwt.verify(req.token, 'secureKey', (err, authorizedData) => {
        if(err){
            res.setHeader('Content-type','application/json ; charset=utf-8');
            console.log('ERROR: Could not connect to the protected route');
            res.sendStatus(403);
            res.end();
        }
        else {
            if(authorizedData.user.role_id==1) {
                db.Produit.create({
                    name:req.body.name,
                    price:req.body.price,
                    photo:'./default/produit.jpg',
                    desc:req.body.desc
                })
                .then(produit=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json(produit);
                    res.status(200);
                    res.end();
                })
                .catch(error=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json(error);
                    res.status(400).send('400 Error');
                    res.end();
                });
            }
        }
    });
});
// END CREATE NEW PRODUIT (PROTECTED BY ROLE_ID (1=ADMIN))

// BEGIN PROTECTED EDIT
router.put('/edit/:id', checkToken, (req, res) => {
    jwt.verify(req.token, 'secureKey', (err, authorizedData) => {
        if(err){
            res.setHeader('Content-type','application/json ; charset=utf-8');
            console.log('ERROR: Could not connect to the protected route');
            res.sendStatus(403);
            res.end();
        }
        else {
            if(authorizedData.user.role_id==1) {
                db.Produit.update({
                    name:req.body.name,
                    price:req.body.price,
                    desc:req.body.desc
                    },{
                    where:{
                        'id':req.params.id
                    }
                })
                .then(produit=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json(produit);
                    res.status(200);
                    res.end();
                })
                .catch(error=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json(error);
                    res.status(400).send('400 Error');
                    res.end();
                });
            }
            else {
                res.setHeader('Content-type','application/json ; charset=utf-8');
                console.log('ERROR: Access Denied');
                res.sendStatus(403);
                res.end();
            }
        }
    });
});
// END PROTECTED EDIT

// BEGIN PROTECTED PHOTO UPLOAD
router.put('/photo/:id', checkToken, upload.single('photo'), (req, res) => {
    jwt.verify(req.token, 'secureKey', (err, authorizedData) => {
        if(err){
            res.setHeader('Content-type','application/json ; charset=utf-8');
            console.log('ERROR: Could not connect to the protected route');
            res.sendStatus(403);
            res.end();
        }
        else {
            if(authorizedData.user.role_id==1 || authorizedData.user.id==req.params.id) {
                db.Produit.update({
                    photo:'./uploads/'+req.file.filename
                    },{
                    where:{
                        'id':req.params.id
                    }
                })
                .then(photo=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json('Photo uploaded');
                    res.status(200);
                    res.end();
                })
                .catch(error=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json(error);
                    res.status(400).send('400 Error');
                    res.end();
                });
            }
            else {
                res.setHeader('Content-type','application/json ; charset=utf-8');
                console.log('ERROR: Access Denied');
                res.sendStatus(403);
                res.end();
            }
        }
    });
});
// END PROTECTED PHOTO UPLOAD

// BEGIN PROTECTED DELETE
router.delete('/delete/:id', checkToken, (req, res) => {
    jwt.verify(req.token, 'secureKey', (err, authorizedData) => {
        if(err){
            res.setHeader('Content-type','application/json ; charset=utf-8');
            console.log('ERROR: Could not connect to the protected route');
            res.sendStatus(403);
            res.end();
        }
        else {
            if(authorizedData.user.role_id==1) {
                db.Produit.destroy({
                    where:{
                        'id': req.params.id
                    }
                })
                .then(produit=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json('Produit deleted');
                    res.status(200);
                    res.end();
                })
                .catch(error=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json(error);
                    res.status(400).send('400 Error');
                    res.end();
                });
            }
            else {
                res.setHeader('Content-type','application/json ; charset=utf-8');
                console.log('ERROR: Access Denied');
                res.sendStatus(403);
                res.end();
            }
        }
    });
});
// END PROTECTED DELETE

module.exports = router;