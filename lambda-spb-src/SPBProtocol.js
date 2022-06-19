const forge = require('node-forge');

const FileUtils = require('./utils/FileUtils.js');

const zlib = require("zlib");

const fs = require('fs');



module.exports = class SPBProtocol {

    HEADER_SIZE = 588;
    SERIAL_NUMBER_SIZE = 32;
    STRING_SERIAL_NUMBER_SIZE = 16;
    BUFFER_SIZE = 256;
    PADDING_SIZE = 8;
    fileUtils = new FileUtils();


    constructor(pathCertOrigem, senhaCertOrigem, pathCertDest, senhaCertDest) {
        this.pathCertOrigem = pathCertOrigem;
        this.pathCertDest = pathCertDest;
        var certBufferOrigem = this.fileUtils.getFile(pathCertOrigem);
        var certBufferDest = this.fileUtils.getFile(pathCertDest);
        this.certOrigem = this.getCertificate(certBufferOrigem, senhaCertOrigem)
        this.certDestino = this.getCertificate(certBufferDest, senhaCertDest);

        this.privateKeyOrigem = this.getPrivateKey(certBufferOrigem, senhaCertOrigem)
        this.privateKeyDest = this.getPrivateKey(certBufferDest, senhaCertDest);
    }

    getCertificate(bufferP12, senha) {
        var p12Asn1 = forge.asn1.fromDer(bufferP12);
        var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);
        var bags = p12.getBags({ bagType: forge.pki.oids.certBag });
        var certInfo = bags[forge.pki.oids.certBag][0];
        return certInfo;
    }
    getPrivateKey(bufferP12, senha) {
        var p12Asn1 = forge.asn1.fromDer(bufferP12);
        var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);
        var bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
        var privateKey = bags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
        // console.log(privateKey);
        return privateKey;
    }

    getDestSerial() {
        return this.certOrigem.cert.serialNumber.toUpperCase().padStart(32, '0');
    }
    getOrigSerial() {
        return this.certDestino.cert.serialNumber.toUpperCase().padStart(32, '0');
    }


    signAndEncrypt() {
        var buff = Buffer.alloc(this.HEADER_SIZE)
        buff.writeIntBE(this.HEADER_SIZE, 0, 2)
        var offset = 3;
        buff.writeIntBE(2, offset++, 1); // c02 - Protocol Version
        buff.writeIntBE(0, offset++, 1); // c03 - Error Code
        buff.writeIntBE(8, offset++, 1); // c04 - Special Treatment Indicator:
        buff.writeIntBE(0, offset++, 1); // c05 - Reservado
        buff.writeIntBE(2, offset++, 1); // C06 - destAsymmetricAlgorithm:
        buff.writeIntBE(1, offset++, 1); // C07 - symmetricAlgorithm:
        buff.writeIntBE(2, offset++, 1); // C08 - asymmetricAlgorithm :
        buff.writeIntBE(3, offset++, 1); // C09 - hashAlgorithm: 02H: SHA-1, 03H: SHA-256
        buff.writeIntBE(4, offset++, 1); // C10 - destCertCa:
        buff.write(this.getDestSerial(), offset++, 32); // C11 - destination Certificate Serial Number
        offset = offset + 32;
        buff.writeIntBE(4, offset++, 1); // C12 - signatureCertCa
        buff.write(this.getOrigSerial(), offset++, 32); // C13 - signature Certificate Serial Number - Local
        offset = offset + 32;


        // console.log(this.certOrigem);
        var md = forge.md.sha1.create();
        var xml = this.fileUtils.getFile("../agen.xml");
        var conteudo = zlib.gzipSync(xml)

        // console.log('Conteudo Aberto: ' + conteudo.toString('hex'));

        md.update(conteudo, 'binary');
        var signature = this.privateKeyOrigem.key.sign(md);

        var keyDESede = this.generate3DESKey()
        var encryptedKey = this.certOrigem.cert.publicKey.encrypt(keyDESede);

        // console.log("KEY: " + Buffer.from(forge.util.createBuffer(encryptedKey).getBytes(this.BUFFER_SIZE)).toString('hex'));

        // console.log("Signature: " + Buffer.from(forge.util.createBuffer(signature).getBytes()).toString('hex'));

        buff.write(encryptedKey, offset++, this.BUFFER_SIZE); // C14 - encryptedSymmetricKey
        offset = offset + this.BUFFER_SIZE;

        buff.write(signature,offset++,this.BUFFER_SIZE)


        var cipher   = forge.cipher.createCipher('3DES-CBC', keyDESede);
        cipher.start({iv:forge.random.getBytesSync(8)});
        cipher.update(forge.util.createBuffer(conteudo, 'utf-8'));
        cipher.finish();
        var encrypted = Buffer.from(cipher.output.getBytes());
        // console.log('Header: '+ buff.toString('hex'));

        // console.log('Content: '+ encrypted.toString('hex'));

        var byteArr = [buff, encrypted];
        const finalBuff = Buffer.concat(byteArr);

        fs.createWriteStream('../req.gz.dat').write(finalBuff);

        return finalBuff;
    }

    generate3DESKey() {
        // 3DES key and IV sizes
        var keySize = 24;
        var ivSize = 8;
        var salt = forge.random.getBytesSync(8);
        var derivedBytes = forge.pbe.opensslDeriveBytes(
            forge.random.getBytesSync(keySize), salt, keySize + ivSize);
        var buffer = forge.util.createBuffer(derivedBytes);
        var key = buffer.getBytes(keySize);
        return key;
    }



}

// 4c 02 00 02 00 08 00 02 01 02 03 04
// 4c 02 00 02 00 08 0102 0302 3004 3030 3030 //java
