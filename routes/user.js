let express = require('express');
let router = express.Router();
let db = require(`../models/index.js`);

// bcrypt
const bcrypt = require('bcrypt');
const saltRounds = 10;

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
    db.User.findAll({})
    .then(users=>{
        res.setHeader('Content-type','application/json ; charset=utf-8');
        res.json(users);
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

// BEGIN PROTECTED SHOW DETAILS
router.get('/profile/:id', checkToken, (req, res) => {
    //verify the JWT token generated for the user
    jwt.verify(req.token, 'secureKey', (err, authorizedData) => {
        if(err){
            //If error send Forbidden (403)
            res.setHeader('Content-type','application/json ; charset=utf-8');
            console.log('ERROR: Could not connect to the protected route');
            res.sendStatus(403);
            res.end();
        }
        else {
            if(authorizedData.user.role_id==1 || authorizedData.user.id==req.params.id) {
                db.User.findOne({
                    where:{
                        'id': req.params.id
                    }
                })
                .then(user=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json(user);
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
// END PROTECTED SHOW DETAILS

// BEGIN PROTECTED LOGIN
router.post('/login',(req,res)=>{
    db.User.findOne({
        where:{
            name: req.body.name
        }
    })
    .then(user=>{
        if(!user){
            res.setHeader('Content-type','application/json ; charset=utf-8');
            res.json({'message':'Login = KO : User not found'});
            res.status(400);
            res.end();
        }
        bcrypt.compare(req.body.password, user.password, (err,result)=>{
            if (result) {
                // Creation du token
                jwt.sign({user}, 'secureKey', {expiresIn: '1h'}, (err, token)=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    if(err) {
                        console.log(err);
                        res.status(400);
                    }
                    res.json(token);
                    res.status(200);
                    res.end();
                });
            }
            else {
                res.setHeader('Content-type','application/json ; charset=utf-8');
                res.json({'message':'Login = KO : Password does not match'});
                res.status(400);
                res.end();
            }
        });
    });
});
// END PROTECTED LOGIN

// BEGIN CREATE NEW USER (PUBLIC) (NEW USER ROLE_ID = 2 (STANDARD USER), AVATAR = DEFAULT AVATAR)
router.post('/create', (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, (err, hash)=> {
        db.User.create({
            name:req.body.name,
            age:req.body.age,
            email:req.body.email,
            avatar:'./default/avatar.jpg',
            password:hash,
            role_id:2
        })
        .then(user=>{
            res.setHeader('Content-type','application/json ; charset=utf-8');
            res.json(user);
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
});
// END CREATE NEW USER (PUBLIC)

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
            // Admins can change role_id, users cannot
            if(authorizedData.user.role_id==1 || authorizedData.user.id==req.params.id && authorizedData.user.role_id==req.body.role_id) {
                bcrypt.hash(req.body.password, saltRounds, (err, hash)=> {
                    db.User.update({
                        name:req.body.name,
                        age:req.body.age,
                        email:req.body.email,
                        password:hash,
                        role_id:req.body.role_id
                        },{
                        where:{
                            'id':req.params.id
                        }
                    })
                    .then(user=>{
                        res.setHeader('Content-type','application/json ; charset=utf-8');
                        res.json(user);
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

// BEGIN PROTECTED AVATAR UPLOAD
router.put('/avatar/:id', checkToken, upload.single('avatar'), (req, res) => {
    jwt.verify(req.token, 'secureKey', (err, authorizedData) => {
        if(err){
            res.setHeader('Content-type','application/json ; charset=utf-8');
            console.log('ERROR: Could not connect to the protected route');
            res.sendStatus(403);
            res.end();
        }
        else {
            if(authorizedData.user.role_id==1 || authorizedData.user.id==req.params.id) {
                db.User.update({
                    avatar:'./uploads/'+req.file.filename
                    },{
                    where:{
                        'id':req.params.id
                    }
                })
                .then(avatar=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json('Avatar uploaded');
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
// END PROTECTED AVATAR UPLOAD

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
            if(authorizedData.user.role_id==1 || authorizedData.user.id==req.params.id) {
                db.User.destroy({
                    where:{
                        'id': req.params.id
                    }
                })
                .then(user=>{
                    res.setHeader('Content-type','application/json ; charset=utf-8');
                    res.json('User deleted');
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