/**
 * Created by olzi on 23.08.2016.
 */
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var personSchema = new Schema({
    username: String,
    publicKey: String, //Public key of the PKI
    privateKeyEnc: String, //Encrypted private key of the PKI, encrypted using password (symmetric encryption currently)
    encryptionKeyEnc: String //Encrypted encryption key used to encrypt data, encrypted using the public key
});



//module.exports = mongoose.model('personSchema', personSchema);