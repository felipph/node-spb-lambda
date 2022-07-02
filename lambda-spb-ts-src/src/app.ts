import * as fs from 'fs';
import { SPBHeader } from './service/spb/model/SPBHeader';
import { FileUtils } from './utils/FileUtils';
import { SPBProtocolV2 } from './service/spb/impl/SPBProtocolV2';

import {S3CreateEvent} from "aws-lambda";
import * as AWS from "aws-sdk";


exports.lambdaHandler = async (event:S3CreateEvent, context:any) => {

    const s3 = new AWS.S3();
    
    const bucket = event.Records[0].s3.bucket.name;
    const key = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, ' '));
    var headerContent:Buffer;
    await s3.getObject({ Bucket: bucket, Key: key, Range: '0-587' }, (err,data) => {
        if(!err) {
            headerContent = data.Body as Buffer;
        }
    }).promise();

    console.log(headerContent);
    

    var header = new SPBHeader(headerContent);
    console.log(header);    

    return {
        statusCode: 200,
        body: `Recebido: ${key}`
    }
};

// async function main() {

//     const filePath = '../req.gz.dat';
//     const fd = fs.openSync(filePath, 'r'); // file descriptor
//     const stats = fs.statSync(filePath); // file details

//     var sharedBuffer = Buffer.alloc(SPBHeader.getHeaderSize());
//     //carregando somente o header    
//     await FileUtils.readBytes(fd, sharedBuffer);
//     var header = new SPBHeader(sharedBuffer);
//     console.log(header);

//     var contentSize = stats.size - SPBHeader.getHeaderSize();
//     sharedBuffer = Buffer.alloc(contentSize);

//     await FileUtils.readBytes(fd, sharedBuffer, 588);
//     const protocol = new SPBProtocolV2(sharedBuffer, header);

//     var publicKey = fs.readFileSync("./certDestino/publicKeyDestino.pem");

//     var privateKey = fs.readFileSync("./certDestino/privateKeyDestino.pem");

//     const symetricKey = protocol.decryptSymetricKey(privateKey);
//     console.log(symetricKey.toString('utf-8'))

//     protocol.decryptContents();
//     var publicKeyOrigem = fs.readFileSync("./certOrigem/publicKeyOrigem.pem");
//     if (!protocol.checkSignature(publicKeyOrigem)) {
//         console.log("Assinatura inválida!");
//     }
//     console.log(protocol.unpack());
// }

// main().then((ok) => {
//     const used = process.memoryUsage();
//     for (let key in used) {
//         console.log(`${key} ${Math.round(used[key as keyof typeof used] / 1024 / 1024 * 100)} KB`);
//     }
// });
