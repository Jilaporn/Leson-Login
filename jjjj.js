// *Copyright:https://www.npmjs.com/package/cookie-encrypter, using the code to encrypt a cookie
// *Copyright:https://www.w3resource.com/node.js/nodejs-mysql.php, using connect node.js server with mysql
// *Copyright:https:https://stackoverflow.com/questions/7480158/how-do-i-use-node-js-crypto-to-create-a-hmac-sha1-hash ,using crypto to hash the data that confirmly come from me
// *Project: code from stackoverflow page https://stackoverflow.com/questions/5710358/how-to-retrieve-post-query-parameters, using app.post,app.use
// *Copyright:https://www.tutorialspoint.com/nodejs/nodejs_express_framework.htm, using express(web application framework provides robust set of features to develop web
// *Copyright:https://expressjs.com/en/resources/middleware/cors.html, using cors
// *Copyright: https://nodejs.org/api/crypto.html, HMAC(creating cryptographic HMAC digests),sekai is the key that sever and receiver use to send the file
// *Copyright: https://www.abeautifulsite.net/hashing-passwords-with-nodejs-and-bcrypt, using bcrypt code to hash and compare the password: it will have the first password that we set then input the password will hash and compare the hash with password in mysql,it will reduce the risk of crash during sending same password at the same time
// *Copyright: https://stackoverflow.com/questions/16209145/how-to-set-cookie-in-node-js-using-express-framework ,using cookie to link code with Bright by using cookie name sekai
// *Copyright: https://itnext.io/node-express-letsencrypt-generate-a-free-ssl-certificate-and-run-an-https-server-in-5-minutes-a730fbe528ca, using certificate,privatekey, credential code to do a https
var express = require("express")
const https = require('https');
const fs = require('fs');
//var sha256 = require("js-sha256")
var app = express()
var cors = require("cors")
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var bcrypt = require('bcrypt');
var crypto = require('crypto');
const saltRounds = 10;
//.. directory now
const cookieEncrypter = require('cookie-encrypter');
//32 alphabets: 32 bits
const secretKey = 'lesonprojectfromxinbrightfrong22';
//var jsonParser = bodyParser.json()
//var urlencodeParser = bodyParser.urlencoded({extended: false})

// Certificate
const privateKey = fs.readFileSync('/etc/letsencrypt/live/bright.ikirize.net/privkey.pem', 'utf8');
const certificate = fs.readFileSync('/etc/letsencrypt/live/bright.ikirize.net/cert.pem', 'utf8');
const ca = fs.readFileSync('/etc/letsencrypt/live/bright.ikirize.net/chain.pem', 'utf8');

const credentials = {
    key: privateKey,
    cert: certificate,
    ca: ca
};

app.use(cookieParser(secretKey));
app.use(cookieEncrypter(secretKey));

app.use(cors())
app.use(cookieParser());
app.use(express.json())
app.use(express.urlencoded());
app.use(bodyParser.json());
var mysql = require('mysql');
var connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Kormadikrub"
});

connection.connect(function (err) {
    if (err) {
        console.error('error connecting: ' + err.stack);
        return;
    }
    console.log('connected as id ' + connection.threadId);
});


app.get('/', function (req, res) {
    res.sendFile('/root/final/xincode/xin code/firstpage.html');
});

app.post('/login', function (req, res) {
    //res.cookie('sekai', 'a')
    console.log(req.cookies)
    connection.query('SELECT password FROM kormadikrubdatabase.p2p WHERE name=?', [req.body.username], function (err, results, fields) {
        const cookieParams = {
            maxAge: 100000,
            plain:true
          };
        
        if (results[0]) {
            console.log("res body: ", req.body.password);
            console.log("hash pass: ", results[0]);
            bcrypt.compare(req.body.password, results[0].password).then(function (compare_res) {
                console.log("compare result: ", compare_res);
                if (compare_res) {
                    connection.query('SELECT name,positions FROM kormadikrubdatabase.p2p WHERE name=?', [req.body.username], function (errs, resultss) {
                        console.log(resultss[0]);

                        var hash = crypto.createHmac('sha1', "sekai").update(resultss[0]['name'] + resultss[0]['positions']).digest('hex')
                        resultss[0]['hash'] = hash
                        resultss[0]['valid'] = 'true';
                        
                        res.cookie('sekai', cookieEncrypter.encryptCookie(resultss[0]['name'] +":"+ resultss[0]['positions']+":"+ hash,{"key":secretKey}), cookieParams)
                        res.send(resultss[0]);
                    });
                }
                else {
                    console.log('invalid');
                    res.send({ 'valid': 'false' });
                }
            });

            // Passwords don't match
        }
        else {
            console.log('invalid');
            res.send({ 'valid': 'false' });
            // Passwords don't match
        }
    });

});


//app.listen(3000,()=>{})

const httpsServer = https.createServer(credentials, app);

httpsServer.listen(3000, () => {
});
