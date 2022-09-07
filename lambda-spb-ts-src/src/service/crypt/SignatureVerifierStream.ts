import { Transform, TransformOptions, TransformCallback } from "node:stream";
import * as crypto from "crypto"


export class SignatureVerifierStream extends Transform {

    private _hashType: any;
    private _verifier: any;
    private _signatureBuf: any;
    private _publicKey: any;
    private _status: any;

    constructor(opts: any) {
        super(opts);
        this._hashType      = opts.hashType;
        this._signatureBuf  = opts.signatureBuf;
        this._publicKey     = opts.publicKey;
        this._verifier = crypto.createVerify(this._hashType);

    }

    _transform(chunk: any, enc: BufferEncoding, cb: TransformCallback): void {        
        this._verifier.update(chunk)
        this.push(chunk);             
        cb();
    }

    _flush(cb: TransformCallback) {
        let check = this._verifier.verify(this._publicKey, this._signatureBuf)
        if(check === false) {
            cb(new Error("Assinatura Inválida!"));
            return;
        }
        this._status = "SIGN_OK";
        console.info("Assinatura OK")
        cb();
    }

    getStatus() {
        return this._status;
    }

}