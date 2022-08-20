import { Transform, TransformOptions, TransformCallback } from "node:stream";
import * as crypto from "crypto"

export class EncryptStream extends Transform {

    private cipher:any;

    constructor(opts: any) {
      super(opts);

        const cipherName = opts.cipherName;
        const key = opts.key;
        const iv = opts.key;

      this.cipher = crypto.createCipheriv(cipherName, key, iv);
      this.push(iv);
    }
  
    _transform(chunk: any, enc: BufferEncoding, cb: TransformCallback) {
      this.push(this.cipher.update(chunk));
      cb();
    }
  
    _flush(cb:any) {
      this.push(this.cipher.final());
      cb();
    }
  
}