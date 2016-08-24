var express = require('express');
var passport = require('passport');
var mongoose = require('mongoose');

var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function () {
    console.log("We are connected!");
});

var Account = require('../models/account');
var crypto = require('crypto');
var nodeforge = require('node-forge');


var router = express.Router();

var algorithm = "aes-256-ctr";


router.get('/', function (req, res) {
    res.render('index', {user: req.user});
});

router.get('/register', function (req, res) {
    res.render('register', {});
});
var Schema = mongoose.Schema;

var personSchema = new Schema({
    username: String,
    publicKey: String, //Public key of the PKI
    privateKeyEnc: String, //Encrypted private key of the PKI, encrypted using password (symmetric encryption currently)
    encryptionKeyEnc: String, //Encrypted encryption key used to encrypt data, encrypted using the public key
    spirometryData: []
});


var Person = mongoose.model('personSchema', personSchema);

/**
 * On registry, a new user is created. additionally, a PKI key pair is created and a symmetric encryption key.
 */
router.post('/register', function (req, res) {
    Account.register(new Account({username: req.body.username}), req.body.password, function (err, account) {
        if (err) {
            return res.render('register', {account: account});
        }

        /*
         * I will now just blindly add everything here without much structure or anything.
         * Refactoring will do the trick afterwards.
         * So the idea is to create all required keys and encrypt them appropriately.
         * The private key is encrypted using the password, the encryption key is encrypted using the private key.
         * the encryption key currently is just a simple string containing some numbers and letters, may be something different entirely depending on the requirements.
         * Person needs to add more fields (address, age, etc.) and also data items I assume?
         *
         * */

        var keyPair = createKeyPair();
        var privateKeyEnc = symmetricEncrypt(keyPair.privateKey, algorithm, req.body.password);
        var encryptionKey = generateUUID(); //TODO replace with real library
        var encryptionKeyEnc = encryptStringWithRsaPublicKey(encryptionKey, keyPair.publicKey);

        console.log("username: " + req.body.username + "\npublicKey: " + keyPair.publicKey + "\nprivate key: " + keyPair.privateKey + "\nprivateKeyEnc: " + privateKeyEnc + "\nencryptionKey: " + encryptionKey + "\nencryptionKeyEnc: " + encryptionKeyEnc)
        var newPerson = new Person({
            username: req.body.username,
            publicKey: keyPair.publicKey,
            privateKeyEnc: privateKeyEnc,
            encryptionKeyEnc: encryptionKeyEnc
        });

        //Adding some dummy data
        var d1 = [
            {
                dateTime: Date.now(),
                FVC: 123,
                FEV1: 123
            },
            {
                dateTime: Date.now(),
                FVC: 456,
                FEV1: 456
            },
            {
                dateTime: Date.now(),
                FVC: 789,
                FEV1: 789
            }

        ]
        var d1String = JSON.stringify(d1[0]);
        var d2String = JSON.stringify(d1[1]);
        var d3String = JSON.stringify(d1[2]);
        console.log("real data d1: " + d1String + "\nd2: " + d2String + "\nd3: " + d3String + "\n");
        var encD1String = symmetricEncrypt(d1String, algorithm, encryptionKey);
        var encD2String = symmetricEncrypt(d2String, algorithm, encryptionKey);
        var encD3String = symmetricEncrypt(d3String, algorithm, encryptionKey);
        console.log("encrypted data d1: " + encD1String + "\nd2: " + encD2String + "\nd3: " + encD3String + "\n");
        newPerson.spirometryData.push(encD1String);
        newPerson.spirometryData.push(encD2String);
        newPerson.spirometryData.push(encD3String);

        console.log("username: " + newPerson.username + "\npublicKey: " + newPerson.publicKey + "\nprivateKeyEnc: " + newPerson.privateKeyEnc + "\encryptionKeyEnc: " + newPerson.encryptionKeyEnc)

        newPerson.save(function (err, newPerson) {
            if (err) {
                console.log("could not save new person with name " + newPerson.username);
                return console.error(err);
            } else {
                console.log("Successfully saved new person with username " + newPerson.username);
            }
        });

        passport.authenticate('local')(req, res, function () {
            res.redirect('/');
        });
    });
});


router.get('/login', function (req, res) {
    res.render('login', {user: req.user});
});


router.post('/login', passport.authenticate('local'), function (req, res) {
    //username & password can be directly taken out of the request body
    var username = req.body.username;
    var password = req.body.password;

    console.log("User: " + username + ", pw: " + password);

    /*
     * Again I will just post the intentions and goals here what to achieve. Not much of a best practiced solution.
     * So when a user logs in with username and password, the private key needs to be decrypted using this password,
     * and then used to decrypt the encryption key, which is then used again to decrypt the data of this user.
     * The problems now are that the decryption may take quite some time the user may not be willing to wait, so
     * it is questionable if the encryption key should only be decrypted once on login and then stored in memory somehow (session, JWT)
     * or instead decrypted on every request (as rest means stateless...)
     */

    Person.findOne({username: username}, function (err, user) {
        console.log("User in db is: " + JSON.stringify(user));
        if (err) {
            console.log("Could not find user with username: " + username);
            res.redirect('/');
        }
        console.log("private key encrypted: " + user.privateKeyEnc);
        //Decrypt the private key using the password in clear text
        var privateKey = symmetricDecrypt(user.privateKeyEnc, algorithm, password);
        console.log(privateKey);
        //Decrypt the encryption key using the decrypted private key
        var encryptionKey = decryptStringWithRsaPrivateKey(user.encryptionKeyEnc, privateKey)
        console.log("encryption key: " + encryptionKey);
        //TODO what to do with the decrypted encryption key? Store it in a session, JWT, or not at all

        //Decrypt the data items and print them to the screen
        for (var i = 0; i < user.spirometryData.length; ++i) {
            var dataItem = symmetricDecrypt(user.spirometryData[i], algorithm, encryptionKey);
            var dataAsJson = JSON.parse(dataItem);
            console.log("Data item " + (i + 1) + " has dateTime: " + dataAsJson.dateTime + " FVC: " + dataAsJson.FVC + ", FEV1: " + dataAsJson.FEV1);
        }
        res.redirect('/');
    });

});

router.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});

router.get('/ping', function (req, res) {
    res.status(200).send("pong!");
});

//TODO maybe use some uid generator library i don't know... looks fine to me
function generateUUID() {
    var d = new Date().getTime();
    var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c == 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
    return uuid;
}
//TODO Refactor ... these functions come from AsymmetricEncryptionHelper.ts and SymmetricEncryptionHelper.ts
function symmetricEncrypt(text, algorithm, encryptionkey) {
    var cipher = crypto.createCipher(algorithm, encryptionkey)
    var crypted = cipher.update(text, 'utf8', 'hex')
    crypted += cipher.final('hex');
    return crypted;
}

function symmetricDecrypt(text, algorithm, encryptionkey) {
    var decipher = crypto.createDecipher(algorithm, encryptionkey)
    var dec = decipher.update(text, 'hex', 'utf8')
    dec += decipher.final('utf8');
    return dec;
}

var encryptStringWithRsaPublicKey = function (textToEncrypt, publicKey) {
    var buffer = new Buffer(textToEncrypt);
    var encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
};
var decryptStringWithRsaPrivateKey = function (textToDecrypt, privateKey) {
    var buffer = new Buffer(textToDecrypt, "base64");
    var decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString("utf8");
};
var createKeyPair = function () {
    var pair = nodeforge.pki.rsa.generateKeyPair();
    var publicKey = nodeforge.pki.publicKeyToPem(pair.publicKey);
    var privateKey = nodeforge.pki.privateKeyToPem(pair.privateKey);
    return {"privateKey": privateKey, "publicKey": publicKey};
};

module.exports = router;