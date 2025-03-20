let jwt = require('jsonwebtoken')
let constants = require('../Utils/constants')
let userController = require('../controllers/users')
module.exports={
    check_authentication: async function(req,res,next){
        if(req.headers.authorization){
            let token_authorization = req.headers.authorization;
            if(token_authorization.startsWith("Bearer")){
              let token = token_authorization.split(" ")[1];
              let verifiedToken = jwt.verify(token,constants.SECRET_KEY);
              if(verifiedToken){
                console.log(verifiedToken);
                let user = await userController.getUserById(
                    verifiedToken.id  
                )
                req.user = user;
                next()
              }
            }else{
              throw new Error("ban chua dang nhap")
            }
          }else{
            throw new Error("ban chua dang nhap")
          }  
    },
    check_authorization: function(roles){
        return function(req,res,next){
            if(roles.includes(req.user.role.roleName)){
                next();
            }else{
                throw new Error("ban khong co quyen")
            }
        }
    }
}