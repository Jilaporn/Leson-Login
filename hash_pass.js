//Copyright@https://www.npmjs.com/package/bcrypt, using to do a hash(setting password) to use in login
const bcrypt = require('bcrypt');
const saltRounds = 10;
const myPlaintexPassword = 'iamurteacher';
bcrypt.hash(myPlaintexPassword, saltRounds, function(err, hash){
  console.log('hash: ', hash)
})