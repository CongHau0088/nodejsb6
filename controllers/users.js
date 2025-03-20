let userSchema = require('../models/users');
let roleSchema = require('../models/roles');
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let constants = require('../Utils/constants')


module.exports = {
    getUserById: async function(id){
        return await userSchema.findById(id).populate("role");
    },
    createUser:async function(username,password,email,role){
        let roleCheck = await roleSchema.findOne({roleName:role});
        if(roleCheck){
            let newUser = new userSchema({
                username: username,
                password: password,
                email: email,
                role: roleCheck._id,
            });
            await newUser.save();    
            return newUser;  
        }else{    
            throw new Error("role khong ton tai");
        }

    },
    checkLogin: async function(username,password){
        if(username&&password){
            let user = await userSchema.findOne({
                username:username
            })
            if(user){
                if(bcrypt.compareSync(password,user.password)){
                    return jwt.sign({
                        id:user._id,
                        expired:new Date(Date.now()+30*60*1000)
                    },constants.SECRET_KEY);
                }else{
                    throw new Error("username or password is incorrect")
                }
            }else{
                throw new Error("username or password is incorrect")
            }
        }else{
            throw new Error("username or password is incorrect")
        }
    }
}