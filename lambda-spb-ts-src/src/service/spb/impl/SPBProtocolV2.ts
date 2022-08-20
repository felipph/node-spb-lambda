import { SPBHeader } from "../model/SPBHeader";
import * as crypto from "crypto"
import * as zlib from "zlib"


export class SPBProtocolV2 {

    header: SPBHeader;
    openContent: Buffer;
    symetricKey: Buffer;
    inflatedContent: String;
    iv: Buffer;

    constructor(header: SPBHeader) {
        this.header = header;
    }

    decryptSymetricKey(privateKey: Buffer): Buffer {

        this.symetricKey = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING
            },
            this.header.bufferEncryptedSymetricKey);
        this.iv = this.symetricKey.slice(0,8)
        return this.symetricKey;
    }


    checkSignature(publicKey: Buffer): boolean {
        if (this.openContent == null) {
            throw new Error("Primeiro é necessário depriptar o conteúdo!")
        }
        var verifier = crypto.createVerify("SHA256");
        verifier.update(this.openContent)
        return verifier.verify(publicKey,this.header.bufferSignature);
    }
    decryptContents(encriptedContent: Buffer): Buffer {
        if(this.symetricKey == null) {
            throw new Error('Chave Simétrica não disponível!');
        }        
        const decipher3des = crypto.createDecipheriv('des-ede3-cbc', this.symetricKey, this.iv)
        decipher3des.setAutoPadding(false)
        var decrypted = decipher3des.update(encriptedContent)
        this.openContent = Buffer.concat([decrypted,decipher3des.final()]);
        return this.openContent;
    }

    decryptToS3(): void {

    }

    unpack(): String {
        this.inflatedContent = zlib.gunzipSync(this.openContent).toString('utf-8');
        return this.inflatedContent;
    }

}