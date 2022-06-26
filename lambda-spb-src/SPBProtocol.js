const forge = require('node-forge');

const FileUtils = require('./utils/FileUtils.js');

const admzip = require("adm-zip");

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
        buff.write(this.getDestSerial(), offset++, 32); // C11 - destination Certificate Serial Number
        offset = offset + 31;
        buff.writeIntBE(4, offset++, 1); // C12 - signatureCertCa
        buff.write(this.getOrigSerial(), offset++, 32); // C13 - signature Certificate Serial Number - Local
        offset = offset + 31;

        
        var xml = this.fileUtils.getFile(filePath);

        var zip = new admzip();

        zip.addFile('req.xml',xml,'utf8');

        var conteudo =  zip.toBuffer();

        // fazendo o padding do conteudo...

        var fileLengthBeforePadding = conteudo.length;
		const PADDING_LENGTH = 8;
		
		var paddingLength = PADDING_LENGTH - (fileLengthBeforePadding % PADDING_LENGTH);
        if (paddingLength == PADDING_LENGTH) {
            paddingLength = 0;
        }
        
        //Se for necessário fazer padding
        // if(paddingLength != 0) {
        //     console.log("Padding do arquivo...")
        //     conteudo = Buffer.concat([Buffer.from(conteudo)], Buffer.alloc(paddingLength))
        // }

        fs.createWriteStream('../req.gz').write(conteudo);

        //ASSINATURA
        var md = forge.md.sha256.create();
        md.update(conteudo, 'binary');
        var signature = this.privateKeyOrigem.key.sign(md);

        console.log('Signature: ' + Buffer.from(signature, 'binary').toString('hex'));

        var keyDESede = Buffer.from("ThisIsSpartaThisIsSparta");
        
        var encryptedKey = Buffer.from(this.certDestino.cert.publicKey.encrypt(keyDESede),'binary');

        console.log('Chave crypt: ' );
        console.log(encryptedKey.length);
        console.log(encryptedKey.toString('hex'));
        var decryptedKey = this.privateKeyDest.key.decrypt(encryptedKey);
        
        console.log('Chave Aberta ' + decryptedKey);
 

        buff = Buffer.concat([buff, encryptedKey]); // C14 - encryptedSymmetricKey
        offset = offset + this.BUFFER_SIZE;

        buff = Buffer.concat([buff, Buffer.from(signature,'binary')]);

        var encrypted = Buffer.from(this.encrypt(conteudo,keyDESede));
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

    verifySignDecrypt(filePath){

        console.log("Descriptando!");
        
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

        var content = buffer.slice(this.HEADER_SIZE);

        var chaveAberta = this.privateKeyDest.key.decrypt(chaveSimetricaCriptografada.toString('binary'));     

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

        var inflatedData = zlib.gunzipSync(Buffer.from(decrypted, 'binary'))

        return inflatedData.toString('utf8');

    }

    decrypt(encryptedBuffer, key) {
        let buffKey = Buffer.from(key, 'utf-8')        
        const decipher3des = crypto.createDecipheriv('des-ede3-cbc', buffKey, buffKey.slice(0,8))
        decipher3des.setAutoPadding(false)
        let decrypted = decipher3des.update(encryptedBuffer,'binary','binary')
        decrypted += decipher3des.final('binary')   
        return decrypted     
    }

    encrypt(openBuffer, key) {

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


        console.log('Tamanho: '+ openBuffer.length)

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

/**
 * 0000000000000000A3561B8BEC43CC1D
 * 0000000000000000A3561B8BEC43CC1D
 * b6f1a8
 * 9a 56 bd c1 cc f0 a3 8c 39 f7 2f 71 17 34 49 ec a5 02 fb 70 2a dd 5e 
 * 88dfb3546dee251abd16561155d63c34ceda47a39c4e9269757c1fe1b0ca9fa72ed86076fcb43239eee1cf62d7d465b4fe22ec14aa33e4282d76e6f3ade139d9eade4f3b7b674a6649771166ce018b72e3cc9afd1e050e29154c45c2bf207e95fa72a69ec08b4e53006df889c90583bf8423bfc5d05ae074ad129350728b2639b5f429f234192ab975ea7f8b6e70165eb4f1d00b38be59547c45045ce76af1e7e81ca1f00cf9b203ebb5c9582eee657364c1d90143283d53dac7de41509345b9adbf41e9555f907e14767896db3bb0c162173eefcd0ee1ccf2cd9c48436790a6ec7c22b1004299cdae1109b38a41edc375d0ed57f986faf152dcf86045fe1ba2
 */