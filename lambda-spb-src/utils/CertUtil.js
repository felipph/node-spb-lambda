const FileUtils = require('./FileUtils');
var rs = require('jsrsasign');
var rsu = require('jsrsasign-util');
var path = require('path');



module.exports = class CertUtil {

    getCertificate(path, pass){
        keyStr = rsu.readFile(keyFileOrStr);
        var c = new rs.X509();
        c.readCertPEM
        c.readFile(fileUtils.getFile('../sender.p12'));
        var hSerial    = c.getSerialNumberHex(); // '009e755e" hexadecimal string
        var sIssuer    = c.getIssuerString();    // '/C=US/O=z2'
        var sSubject   = c.getSubjectString();   // '/C=US/O=z2'
        var sNotBefore = c.getNotBefore();       // '100513235959Z'
        var sNotAfter  = c.getNotAfter();        // '200513235959Z'
            }


}