'use strict';
var forge = require("node-forge");
var pki = forge.pki;
var key = pki.rsa.generateKeyPair();
console.log(JSON.stringify(key.privateKey));
