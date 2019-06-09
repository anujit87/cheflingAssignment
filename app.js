const express=require('express');
const mysql=require('mysql');
const path = require('path');
const bodyParser=require('body-parser');
const {check, validationResult} =require('express-validator/check')
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');

const db=mysql.createConnection({
    host:'localhost',
    user:'root',
    password:'password',
    database:'users_db'
})

db.connect((err)=>{
    if(err) throw err;
    console.log('Connected to Database')
});

const app = express();

app.set('view engine','ejs');
app.set('views',path.join(__dirname,'views'))

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:false}));


app.get('/user/signin',(req,res)=>{
    res.render('login',{errors:[]});
})

app.get('/user/signup',(req,res)=>{
    res.render('signup',{errors:[]});
})

/*app.get('/createdb',(req,res)=>{
    let sql='CREATE DATABASE users_db';
    db.query(sql,(err,result)=>{
        if(err) throw err;
        console.log(result);
        res.send('Database created');
    })
});*/

app.get('/createuserstable',(req,res)=>{
    let sql ='CREATE TABLE users(id int AUTO_INCREMENT, name VARCHAR(255), email VARCHAR(255), password VARCHAR(255), PRIMARY KEY(id))';
    db.query(sql,(err,result)=>{
        if(err) throw err;
        console.log(result);
        res.send('Users table created.....')
    })
});

//Signup API for Adding user to database
app.post('/user/signup',[
    check('email').isEmail().withMessage('Email is Not Valid'),
    check('name').not().isEmpty().withMessage('Name is Required'),
    check('email').not().isEmpty().withMessage('Email is Required'),
    check('password').not().isEmpty().withMessage('Password is Required')
],(req,res,next)=>{
   const errors=validationResult(req);
   if(!errors.isEmpty()){
       return res.render('signup',{errors:errors.array()}) 
   }
   //Hashing the password using bcrypt
   bcrypt.hash(req.body.password,10).then(hash=>{
    let sql='INSERT INTO users SET ?';
    const user={
        name:req.body.name,
        email:req.body.email,
        password:hash
    }

    db.query(sql,user,(err,result)=>{
        if(err) {
            if(err.code==='ER_DUP_ENTRY'){
                const arr=errors.array();
                arr.push({param:'sameuser',msg:'User already Exists'})
                return res.render('signup',{errors:arr}); 
            }
        }
       //console.log(result.insertId);
       const token=jwt.sign({email:req.body.email,userId:result.insertId},"some_secret_about_user");
       //req.token=token;
       req.params.id=result.insertId
       //req.session.token=token;
       return res.redirect(`/user/profile?token=${token}`);
   })

   })
   
   
});

//Signin API
app.post('/user/signin',[
    check('email').isEmail().withMessage('Email is Not Valid'),
    check('email').not().isEmpty().withMessage('Email is Required'),
    check('password').not().isEmpty().withMessage('Password is Required')
],(req,res,next)=>{
    const errors=validationResult(req);
    if(!errors.isEmpty()){
        return res.render('login',{errors:errors.array()}) 
    }
    let findUserSql=`SELECT * FROM users WHERE email='${req.body.email}'`;
    db.query(findUserSql,(err,result)=>{
        if(err){
            const arr=errors.array();
            arr.push({param:'fail',msg:'Some Error Occured'})
            return res.render('login',{errors:arr});
        }
        if(result.length===0){
            const arr=errors.array();
            arr.push({param:'fail',msg:'User Not Found'})
            return res.render('login',{errors:arr})
        }else{
            bcrypt.compare(req.body.password,result[0].password).then(data=>{
                if(!data){
                    const arr=errors.array();
                    arr.push({param:'fail',msg:'Authentication Failed! Please Login Again'})
                    return res.render('login',{errors:arr})
                }
                const token=jwt.sign({email:result[0].email,userId:result[0].id},"some_secret_about_user");
                
                req.params.id=result[0].id;
                return res.redirect(`/user/profile?token=${token}`);

            }).catch(error=>{
                const arr=errors.array();
                arr.push({param:'fail',msg:'Some Error Occured'})
                return res.render('login',{errors:arr});
            })
        }
        
    })
});


app.get('/user/profile',(req,res,next)=>{
    
    const token = req.query.token;
    let error=[];
    if(req.query.error){
        error.push({param:'update-fail',msg:'Update Failed'})
    }
    try{
        if(token){
            const decodedToken = jwt.verify(token, "some_secret_about_user");
            let sql=`SELECT * FROM users WHERE id = ${decodedToken.userId}`;
            db.query(sql,(err,result)=>{
                if(err){
                    return res.render('profile',{result:{},authToken:'',errors:[{param:'fail',msg:'Authentication Failed! Please Login Again'}]})
                }
                return res.render('profile',{result:result[0],authToken:token,errors:error});
            }) 
        }else{
            return res.render('profile',{result:{},authToken:'',errors:[{param:'fail',msg:'Authentication Failed! Please Login Again'}]})
        }
    }catch(err){
        return res.render('profile',{result:{},authToken:'',errors:[{param:'fail',msg:'Authentication Failed! Please Login Again'}]})
    }
     
});

app.post('/user/profile/update',[
    check('email').isEmail().withMessage('Email is Not Valid')
],(req,res,next)=>{
    
    try {
        const errors=validationResult(req);
        const decodedToken = jwt.verify(req.body.token, "some_secret_about_user");
        
        let sql = `UPDATE users SET ? WHERE id=${decodedToken.userId}`;
        let user = {
            name: req.body.name,
            email: req.body.email
        }
        if (req.body.password) {
            bcrypt.hash(req.body.password, 10).then(hash => {
                user.password = hash;
            }).then(data => {
                db.query(sql, user, (err, result) => {
                    if (err) {
                        const error='Update failed';
                        return res.redirect(`/user/profile?token=${req.body.token}&error=${error}`)
                    }
                    return res.redirect(`/user/profile?token=${req.body.token}`);
                })
            })
        } else {
            db.query(sql, user, (err, result) => {
                if (err) {
                    const error='Update failed';
                    return res.redirect(`/user/profile?token=${req.body.token}&error=${error}`)
                }
                return res.redirect(`/user/profile?token=${req.body.token}`);
            })
        }
    } catch (error) {
        return res.render('profile',{result:{},authToken:'',errors:[{param:'invalid',msg:'Some Error Occured'}]})
    }
});


app.listen('3000',()=>{
    console.log('Server started on port 3000');
});