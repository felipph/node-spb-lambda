const forge = require('node-forge');

const {util: {binary: {raw}}} = forge;
const {pki} = forge;

const FileUtils = require('../utils/FileUtils.js');

const fs = require('fs');

const crypto = require('crypto')

const zlib = require('zlib')

module.exports = class SPBProtocol {

    HEADER_SIZE = 76;
    HEADER_TOTAL_SIZE = 588;
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

    generatePem(certP12) {
        var certBufferOrigem = this.fileUtils.getFile(certP12);
        var publicKey = this.getCertificate(certBufferOrigem,'123');
        var privateKey = this.getPrivateKey(certBufferOrigem,'123');

        var privateKeyPEM = pki.privateKeyToPem(privateKey.key);
        var certificatePEM = pki.certificateToPem(publicKey.cert);
        var publicKeyPEM = pki.publicKeyToPem(publicKey.cert.publicKey);

        console.log("PrivateKey: \n " + privateKeyPEM);
        console.log("Certificate: \n " + certificatePEM);
        console.log("PublicKey: \n " + publicKeyPEM);

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


    signAndEncrypt(filePath) {
        var buff = Buffer.alloc(this.HEADER_SIZE)
        buff.writeIntBE(this.HEADER_TOTAL_SIZE, 0, 2) //C1
        var offset = 2;
        buff.writeIntBE(2, offset++, 1); // c02 - Protocol Version
        
        buff.writeIntBE(0, offset++, 1); // c03 - Error Code
        buff.writeIntBE(8, offset++, 1); // c04 - Special Treatment Indicator:
        buff.writeIntBE(0, offset++, 1); // c05 - Reservado
        buff.writeIntBE(2, offset++, 1); // C06 - destAsymmetricAlgorithm:
        buff.writeIntBE(1, offset++, 1); // C07 - symmetricAlgorithm:
        buff.writeIntBE(2, offset++, 1); // C08 - asymmetricAlgorithm :
        buff.writeIntBE(3, offset++, 1); // C09 - hashAlgorithm: 02H: SHA-1, 03H: SHA-256
        buff.writeIntBE(4, offset++, 1); // C10 - destCertCa:
        buff.write(this.getOrigSerial(), offset++, 32); // C11 - destination Certificate Serial Number
        offset = offset + 31;
        buff.writeIntBE(4, offset++, 1); // C12 - signatureCertCa
        buff.write(this.getDestSerial(), offset++, 32); // C13 - signature Certificate Serial Number - Local
        offset = offset + 31;

        
        var xml = this.fileUtils.getFile(filePath);

        var xmlZipped = zlib.gzipSync(xml)
        xmlZipped = this.paddArquivo(xmlZipped);
       
        fs.createWriteStream('../req.gz').write(xmlZipped);
        
        //assinatura        
        var privateKeyPEM = pki.privateKeyToPem(this.privateKeyOrigem.key)
        var signature = crypto.sign("SHA256", Buffer.from(xmlZipped,'binary') , privateKeyPEM);
        // var verified = this.certOrigem.cert.publicKey.verify(md.digest().bytes(), signature);

        // console.log('Check Assinatura: '+ verified)
        
        
        console.log('Signature: ' + signature.toString('hex'));

        var keyDESede = Buffer.from("ThisIsSpartaThisIsSparta");
        
        var encryptedKey = Buffer.from(this.certDestino.cert.publicKey.encrypt(keyDESede),'binary');

        console.log('Chave crypt: ' );
        console.log(encryptedKey.length);
        console.log(encryptedKey.toString('hex'));
        var decryptedKey = this.privateKeyDest.key.decrypt(encryptedKey);
        
        console.log('Chave Aberta ' + decryptedKey);
 

        buff = Buffer.concat([buff, encryptedKey]); // C14 - encryptedSymmetricKey
      
        buff = Buffer.concat([buff, signature]);

        var encrypted = Buffer.from(this.encrypt(Buffer.from(xmlZipped,'binary'), keyDESede), 'binary');
        // console.log('Header: '+ buff.toString('hex'));

         console.log('Content: '+ encrypted.toString('hex'));
         console.log('Tamanho: '+ encrypted.length);

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


    verifySignDecrypt(filePath){
        
        var arquivo = fs.readFileSync(filePath);
        var buffer = Buffer.from(arquivo);
        var offset = 2;
        console.log('C1 => ' + buffer.slice(0,2).toString('hex'));
        console.log('C2 => ' + buffer.slice(offset++,offset).toString('hex'));
        console.log('C3 => ' + buffer.slice(offset++,offset).toString('hex'));
        console.log('C4 => ' + buffer.slice(offset++,offset).toString('hex'));
        console.log('C5 => ' + buffer.slice(offset++,offset).toString('hex'));
        console.log('C6 => ' + buffer.slice(offset++,offset).toString('hex'));
        console.log('C7 => ' + buffer.slice(offset++,offset).toString('hex'));
        console.log('C8 => ' + buffer.slice(offset++,offset).toString('hex'));
        console.log('C9 => ' + buffer.slice(offset++,offset).toString('hex'));        
        console.log('C10 => ' + buffer.slice(offset++,offset).toString('hex'));
        console.log('C11 => ' + buffer.slice(offset++,offset+31).toString());
        offset = offset + 31;
        console.log('C12 => ' + buffer.slice(offset++,offset).toString('hex'));        
        console.log('C13 => ' + buffer.slice(offset++,offset+31).toString());
        offset = offset + 31;

        var chaveSimetricaCriptografada = buffer.slice(offset++,offset+255);

        console.log('C14 => ' + chaveSimetricaCriptografada.toString('hex'));
        offset = offset + 255;

        var assinatura = buffer.slice(offset++,offset+255);
        console.log('C15 => ' + assinatura.toString('hex'));
        offset = offset + 255;

        var content = buffer.slice(this.HEADER_TOTAL_SIZE);

        var chaveAberta = this.privateKeyDest.key.decrypt(chaveSimetricaCriptografada.toString('binary'));    
        
        console.log('ChaveAberta: '+ chaveAberta);

        console.log('Content: '+ Buffer.from(content,'binary').toString('hex'));
        console.log('length: '+ content.length);

        var decrypted = this.decrypt(content,chaveAberta);       


        fs.writeFileSync( '../resp2-js.gz', decrypted, {encoding: 'binary'});

        //verificando assinatura
        console.log(this.getOrigSerial())
        var md = forge.md.sha256.create();
        md.update(decrypted, 'binary');

        var verified = this.certOrigem.cert.publicKey.verify(md.digest().getBytes(), assinatura);
        if(!verified) {
            throw new Error("Assinatura inválida!");
        }
        console.log("Assinatura OK? " + verified);
        console.log("Conteudo: \n" + Buffer.from(decrypted, 'binary').toString('hex'));

        var inflatedData = zlib.gunzipSync(Buffer.from(decrypted, 'binary'))
      

        console.log(inflatedData.toString('utf8'))

    }


    decrypt(encryptedBuffer, key) {
        let buffKey = Buffer.from(key, 'utf-8')        
        const decipher3des = crypto.createDecipheriv('des-ede3-cbc', buffKey, buffKey.slice(0,8))
        decipher3des.setAutoPadding(false)
        let decrypted = decipher3des.update(encryptedBuffer,'binary','binary')
        decrypted += decipher3des.final('binary')   
        return decrypted     
    }


    paddArquivo(openBuffer){
        const PADDING_LENGTH = 8;
		
		var paddingLength = PADDING_LENGTH - (openBuffer.length % PADDING_LENGTH);
        if (paddingLength == PADDING_LENGTH) {
            paddingLength = 0;
        }
        
        // Se for necessário fazer padding
        if(paddingLength != 0) {
            console.log("Padding do arquivo...")
            var padBytes = Buffer.alloc(paddingLength, 0)
            openBuffer = Buffer.concat([openBuffer, padBytes])
        }
        return openBuffer

    }

    encrypt(openBuffer, key) {
        let buffKey = Buffer.from(key, 'utf-8')        
        const decipher3des = crypto.createCipheriv('des-ede3-cbc', buffKey, buffKey.slice(0,8))
        decipher3des.setAutoPadding(false)
        let encrypted = decipher3des.update(openBuffer,'binary','binary')
        encrypted += decipher3des.final('binary')   
        return encrypted     
    }

    bufferToStream(binary) {

        const readableInstanceStream = new Readable({
          read() {
            this.push(binary);
            this.push(null);
          }
        });
    
        return readableInstanceStream;
    }
}
