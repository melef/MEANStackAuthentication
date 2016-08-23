var express = require('express');
var passport = require('passport');
var mongoose = require('mongoose');
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
    encryptionKeyEnc: String //Encrypted encryption key used to encrypt data, encrypted using the public key
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
        var encryptionKey = "Static Random Encryption Key 34895ztrfnihw4htruifhwuiht89ghvnu48957gh8"; //TODO replace with real library
        var encryptionKeyEnc = encryptStringWithRsaPublicKey(encryptionKey, keyPair.publicKey);

        console.log("username: " + req.body.username + "\npublicKey: " + keyPair.publicKey + "\nprivate key: " + keyPair.privateKey + "\nprivateKeyEnc: " + privateKeyEnc + "\nencryptionKey: " + encryptionKey + "\nencryptionKeyEnc: " + encryptionKeyEnc)
        var Person = mongoose.model('Person', personSchema);
        var newPerson = new Person({
            username: req.body.username,
            publicKey: keyPair.publicKey,
            privateKeyEnc: privateKeyEnc,
            encryptionKeyEnc: encryptionKeyEnc
        });
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


//TODO Refactor ... these functions come from AsymmetricEncryptionHelper.ts and SymmetricEncryptionHelper.ts because Typescript throws annoying not found errors.... needs to be fixed.
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


router.get('/login', function (req, res) {
    res.render('login', {user: req.user});
});

router.post('/login', passport.authenticate('local'), function (req, res) {
    //password can be directly taken out of the request body
    var username = req.body.username;
    SymmetricEncryptionHelper.symmetricDecrypt("privatekey", algorithm, req.body.password);

    res.redirect('/');
});

router.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});

router.get('/ping', function (req, res) {
    res.status(200).send("pong!");
});

module.exports = router;