import * as fs from 'fs';
import { SPBHeader } from './service/spb/model/SPBHeader';
import { DecryptStream } from './service/crypt/DecryptStream';
import { SPBProtocolV2 } from './service/spb/impl/SPBProtocolV2';

import {S3Event} from "aws-lambda";
import * as AWS from "aws-sdk";
import { PassThrough } from 'node:stream';
import * as zlib from "zlib"
import { SignatureVerifierStream } from './service/crypt/SignatureVerifierStream';
import * as crypto from "crypto"
const s3 = new AWS.S3(
    {
        endpoint: `http://${process.env.LOCALSTACK_HOSTNAME}:${process.env.EDGE_PORT}`,
        accessKeyId: process.env['AWS_ACCESS_KEY_ID'],
        secretAccessKey: process.env['AWS_SECRET_ACCESS_KEY'],
        region:  process.env['AWS_REGION'],
        s3ForcePathStyle: true       
    }
);   
const {createGunzip} = require('gunzip-stream');
exports.lambdaHandler = async function (event:S3Event, context:any) {
    


    console.log("AQUI EU!");
    
    console.log(event);

    
    const bucket = event.Records[0].s3.bucket.name;
    const size = event.Records[0].s3.object.size;
    const key = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, ' '));

    var headerSPB:Buffer;

    //Obtendo o header SPB

    await s3.getObject({ Bucket: bucket, Key: key, Range: "bytes=0-587"}, (err,data) => {
        if(!err) {
            headerSPB = data.Body as Buffer;
        }
    }).promise();    

    // console.log("ENVIRONMENT VARIABLES\n" + JSON.stringify(process.env, null, 2))
    // console.info("EVENT\n" + JSON.stringify(event, null, 2))
    // console.warn("Event not processed.")
    // console.info("CONTENT: " + headerSPB.toString("hex"));
    // console.info("LENGTH: "  + headerSPB.length);


    var header = new SPBHeader(Buffer.from(headerSPB,0,SPBHeader.getHeaderSize()));
    console.log(header);
    
    var privateKey = fs.readFileSync("./certDestino/privateKeyDestino.pem");
    var publicKey = fs.readFileSync("./certOrigem/publicKeyOrigem.pem");
    
    var protocol = new SPBProtocolV2(header)
    console.log("Chave Simétrica: " + protocol.decryptSymetricKey(privateKey))


    /**
     * MODO para enviar diretamente para o S3 de destino
     */
    //Obtendo o restante e decriptando

    var decryptStream = new DecryptStream({
        cipherName: "des-ede3-cbc",
        key: protocol.symetricKey,
        iv: protocol.iv
    });

    var verifierStream = new SignatureVerifierStream({
            hashType: 'RSA-SHA256',
            signatureBuf: header.bufferSignature,
            publicKey: publicKey
    });


    const uploadStream = (opts:any) => {
        const pass = new PassThrough();
        return {
          writeStream: pass,
          promise: s3.upload({ Bucket:opts.bucket, Key:opts.key, Body: pass }).promise(),
        };
      }

    const { writeStream, promise: uploadS3Promise } = uploadStream({bucket: process.env['BUCKET_DEST'], key: key + '.OPEN'});

    const gunzip = zlib.createGunzip();

    console.log("Obtendo o restante : " + SPBHeader.getHeaderSize() + " até "+ (size-1));
    
    s3.getObject({ Bucket: bucket, Key: key, Range: "bytes="+SPBHeader.getHeaderSize()+"-" + (size-1)}).createReadStream()
    .on('error' ,(e) => {
        throw new Error("Ocorreu um erro + " + e);        
    })
    .pipe(decryptStream)
    .on('end', () => {
        console.info("Decriptografia completada!")
    })
    .pipe(verifierStream)
    .on('end', () => {
        console.info("Assinatura OK completada!")
    })
    .pipe(gunzip)
    .pipe(writeStream)

    console.log("Status Assinatura: " + verifierStream.getStatus());
    
    let sucesso;
    await uploadS3Promise.then(() => {
        console.log('Arquivo gravado no S3!');
        sucesso = 'Arquivo gravado no S3!'
      }).catch((err) => {
        console.log('Falha no upload!', err.message);
        sucesso = 'Falha no upload! ' +  err.message
      });

    return {
        statusCode: 200,
        body: `Recebido: ${key} -> STATUS: ${sucesso}`
    }
};
