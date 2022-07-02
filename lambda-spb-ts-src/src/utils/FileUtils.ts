import * as fs from 'fs';
import { off } from 'process';

export class FileUtils {
    public static readBytes(fd:number, sharedBuffer:Buffer, offset?:number) {
        return new Promise<void>((resolve, reject) => {
            fs.read(
                fd, 
                sharedBuffer,
                0,
                sharedBuffer.length,
                offset,
                (err) => {
                    if(err) { return reject(err); }
                    resolve();
                }
            );
        });
    }
}