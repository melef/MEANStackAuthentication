/**
 * Created by olzi on 23.08.2016.
 */
var mongoose = require('mongoose');
var Schema = mongoose.Schema;


/**
 * Our User model.
 *
 * This is how we create, edit, delete, and retrieve user accounts via MongoDB.
 */
var person = new Schema({
    username: String,
    publicKey: String, //Public key of the PKI
    privateKeyEnc: String, //Encrypted private key of the PKI, encrypted using password (symmetric encryption currently)
    encryptionKeyEnc: String, //Encrypted encryption key used to encrypt data, encrypted using the public key
    spirometryData: []  // measurements
});

var consent = new Schema({
    sender: String, //username of the person giving the consent for her/his data
    receiver: String, //username of the person getting the consent for the other user's data
    encryptionKeyEnc: String //Encrypted encryption key used to decrypt the other users data. Encrypted with public key of the receiver
});

module.exports.Person = mongoose.model('person', person);
module.exports.Consent = mongoose.model('consent', consent);