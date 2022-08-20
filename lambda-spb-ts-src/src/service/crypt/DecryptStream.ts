import { Transform, TransformOptions, TransformCallback } from "node:stream";
import * as crypto from "crypto"


export class DecryptStream extends Transform {

    private _cipherName: any;
    private _decipher: any;

    constructor(opts: any) {
        super(opts);

        this._cipherName = opts.cipherName;
        const key = opts.key;
        const iv = opts.iv;
        this._decipher = crypto.createDecipheriv(this._cipherName, key, iv);
        this._decipher.setAutoPadding(false);

    }

    _transform(chunk: any, enc: BufferEncoding, cb: TransformCallback): void {        
        this.push(this._decipher.update(chunk));             
        cb();
    }

    _flush(cb: TransformCallback) {
        let finalChunk;
        try {
            finalChunk = this._decipher.final();
        } catch (err) {
            return cb(err);
        }
        if (finalChunk.length) {
            this.push(this._decipher.update(finalChunk));             
        }        
        cb();
    }

}