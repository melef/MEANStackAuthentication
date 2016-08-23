
'use strict';


import * as forge from "node-forge";

var pki = forge.pki;
var key = pki.rsa.generateKeyPair();
console.log(JSON.stringify(key.privateKey));
