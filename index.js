var SHA256 = require("crypto-js/sha256");
const Trytes = require('trytes');

var iotaAccount = function(){

  this.SHA256toString = function(input){
    return SHA256(input).toString();
  },

  this.proofofwork = function(input,securityLevel){
    nonce = 0;
    while(this.SHA256toString(input+nonce).substring(0,securityLevel) !== Array(securityLevel + 1).join("0")){
      nonce++;
    }
    resultingHash = this.SHA256toString(input+nonce);
    return resultingHash;
  },
  this.decodeSeed = function (username,password,securityLevel=4)
  {

    console.log('Decoding seed with a security level of: '+securityLevel);
    firstHash = this.proofofwork(username+password,securityLevel);
    secondHash = this.proofofwork(username+password+firstHash,securityLevel);
    thirdHash = this.SHA256toString(username+password+firstHash+secondHash);
    seed = Trytes.encodeTextAsTryteString(thirdHash).substring(0,81);
    return seed;
  }

}

//Initialize script
var iotaAccount = new iotaAccount();

username = 'username';
password = 'password';

securitylevel = 4; // The level of proof of work required to generate seed, default is 4

Seed = iotaAccount.decodeSeed(username,password,securitylevel);

console.log(Seed);
