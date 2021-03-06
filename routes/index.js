var express = require('express');
var passport = require('passport');
var mongoose = require('mongoose');
var uuid = require('node-uuid');

var Account = require('../models/account');
var models = require('../models/user');
var security = require('../security/SecurityUtils');

var db = mongoose.connection;
db.on('error', console.error.bind(console, 'Mongodb connection error:'));
db.once('open', function () {
    console.log("Mongodb is connected!");
});

var router = express.Router();

const algorithm = "aes-256-ctr";

// make dif tests with both values
var useSession = true;
// routers
router.get('/', function (req, res) {
    res.render('index');
});

router.get('/register', function (req, res) {
    res.render('register');
});


// handle end points
/**
 * On registry, a new user is created. additionally, a PKI key pair is created and a symmetric encryption key.
 */
router.post('/register', function (req, res) {
    Account.register(new Account({username: req.body.username}), req.body.password, function (err, account) {
        if (err) {
            console.error("Error while registering user..", err);
            res.locals.error = err.message;
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

        var keyPair = security.createKeyPair();
        var privateKeyEnc = security.symmetricEncrypt(keyPair.privateKey, algorithm, req.body.password);
        var encryptionKey = uuid.v1(); //  some random UUID - is this good to keep? Probably not
        var encryptionKeyEnc = security.encryptStringWithRsaPublicKey(encryptionKey, keyPair.publicKey);

        console.log("username: " + req.body.username + "\npublicKey: " + keyPair.publicKey + "\nprivate key: " + keyPair.privateKey + "\nprivateKeyEnc: " + privateKeyEnc + "\nencryptionKey: " + encryptionKey + "\nencryptionKeyEnc: " + encryptionKeyEnc)
        var newPerson = new models.Person({
            username: req.body.username,
            publicKey: keyPair.publicKey,
            privateKeyEnc: privateKeyEnc,
            encryptionKeyEnc: encryptionKeyEnc
        });

        createDummyData(newPerson, encryptionKey);

        console.log("username: " + newPerson.username + "\npublicKey: " + newPerson.publicKey + "\nprivateKeyEnc: " + newPerson.privateKeyEnc + "\encryptionKeyEnc: " + newPerson.encryptionKeyEnc)
        newPerson.save(function (err, newPerson) {
            if (err) {
                console.error("could not save new person with name " + newPerson.username, err);
                res.locals.error = err.message;
                res.redirect("/register");
            } else {
                console.log("Successfully saved new person with username " + newPerson.username);
            }
        });

        passport.authenticate('local')(req, res, function () {
            res.locals.user = newPerson;
            res.redirect("/");
        });
    });
});


router.post('/login', passport.authenticate('local', {session: useSession}), function (req, res) {

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

    models.Person.findOne({username: username}, function (err, user) {
        console.log("User in db is: " + JSON.stringify(user));
        if (err || !user) {
            console.log("Could not find user with username: " + username);
            res.redirect('/');
        }
        console.log("private key encrypted: " + user.privateKeyEnc);
        //Decrypt the private key using the password in clear text
        var privateKey = security.symmetricDecrypt(user.privateKeyEnc, algorithm, password);
        console.log(privateKey);
        //Decrypt the encryption key using the decrypted private key
        var encryptionKey = security.decryptStringWithRsaPrivateKey(user.encryptionKeyEnc, privateKey)
        console.log("encryption key: " + encryptionKey);
        //TODO what to do with the decrypted encryption key? Store it in a session, JWT, or not at all
        var userDto = {
            username:  user.username,
            data: [],
            consents: []
        };
        var callback = function(err, users) {
            // retrieve all the users I have access (consent) to
            userDto.consentUsers =  getConsentUsers(users);


            // the redirect needs to be here at the callback otherwise the consentUsers are not available for the jade file
            userDto.data = getDecryptedData(user, encryptionKey);
            // make sure we make only limited information of the user available
            res.locals.user = userDto;
            res.render('index');
        };

        models.Consent.find().where('receiver').equals(username).select('sender').exec(callback);

    });

});

router.get('/login', function (req, res) {
    res.render('login');
});
router.get('/grantdataaccess', function (req, res) {

    models.Person.find({}, function (err, people) {
        if (err) {
            console.log("Problem with grantdataaccess.");
            res.render('/');
        }
        var usernames = [];
        for (var i = 0; i < people.length; ++i) {
            usernames.push(people[i].username);
        }
        res.render('grantdataaccess', {usernames: usernames});
    });
});

router.post('/grantdataaccess', passport.authenticate('local', {session: useSession}), function (req, res) {

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
    models.Person.findOne({username: username}, function (err, user) {

        //First of all, get the encryption key of the user and decrypt it
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
        //give the select a name and then you can access the name of the select to retrieve the selected item.

        //Now, get the public key of the user you grant access to, and decrypt the sender's encryption key with it
        models.Person.findOne({username: req.body.receiver}, function (err, person) {
            if (err) {
                res.status(404).send("could not find user with username " + req.body.usernames);
            }

            var encrypteionKeyEnc = security.encryptStringWithRsaPublicKey(encryptionKey, person.publicKey);
            //console.log("Encryption key of sender after encrypting it with public key of receiver:\n" + encrypteionKeyEnc);
            //console.log("PRIVATE KEY: " + person.privateKeyEnc);
           // console.log("Decrypted again: " + decryptStringWithRsaPrivateKey(encrypteionKeyEnc, symmetricDecrypt(person.privateKeyEnc, algorithm, "1")));
            var newConsent = new Consent({
                sender: username,
                receiver: person.username,
                encryptionKeyEnc: encrypteionKeyEnc
            });

            newConsent.save(function (err, newConsent) {
                if (err) {
                    console.log("could not save new consent for user " + newConsent.receiver);
                    return console.error(err);
                } else {
                    console.log("Successfully saved new consent for user " + newConsent.receiver);
                }
            });
            res.status(200).send("new consent added for receiver: " + req.body.receiver + " from sender " + newConsent.sender);
        });
    });

});


router.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});

router.get('/ping', function (req, res) {
    var message = "";
    if (req.user) {
        message = "User is authenticated. Should not happen";
    } else {
        message = "User is not authenticated. Thats what we want";
    }
    res.status(200).send(message);
});

// helper functions
function createDummyData(newPerson, encryptionKey) {
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

    ];
    var d1String = JSON.stringify(d1[0]);
    var d2String = JSON.stringify(d1[1]);
    var d3String = JSON.stringify(d1[2]);
    console.log("real data d1: " + d1String + "\nd2: " + d2String + "\nd3: " + d3String + "\n");
    var encD1String = security.symmetricEncrypt(d1String, algorithm, encryptionKey);
    var encD2String = security.symmetricEncrypt(d2String, algorithm, encryptionKey);
    var encD3String = security.symmetricEncrypt(d3String, algorithm, encryptionKey);
    console.log("encrypted data d1: " + encD1String + "\nd2: " + encD2String + "\nd3: " + encD3String + "\n");
    newPerson.spirometryData.push(encD1String);
    newPerson.spirometryData.push(encD2String);
    newPerson.spirometryData.push(encD3String);
}

function getDecryptedData(user, encryptionKey) {
    var dataDecrypted = [];
    //Decrypt the data items and print them to the screen
    for (var i = 0; i < user.spirometryData.length; ++i) {
        var dataItem = security.symmetricDecrypt(user.spirometryData[i], algorithm, encryptionKey);
        var dataAsJson = JSON.parse(dataItem);
        dataDecrypted.push("Data item " + (i + 1) + " has dateTime: " + dataAsJson.dateTime + " FVC: " + dataAsJson.FVC + ", FEV1: " + dataAsJson.FEV1);
    }
    return dataDecrypted;
}

function getConsentUsers(users) {
    var consentUsers = [];
    console.log("consent user found: " + users.toString())
    for (var i = 0; i < users.length; i++) {
        consentUsers.push(users[i].sender);
    }
    return consentUsers;
}

module.exports = router;