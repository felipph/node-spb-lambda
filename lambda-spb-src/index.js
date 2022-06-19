'use strict'
const AWS = require('aws-sdk');
const zlib = require("zlib");

const s3 = new AWS.S3({ 
    endpoint: `http://localhost:4566`, 
    s3ForcePathStyle: true,
});

spbEncript = function(partyOrigin, partDest, data) {
    var buffer = Buffer.from([0]);


    return buffer;
};

exports.handler = async (event, context, callback) => {
    // Get the object from the event and show its content type
    const bucket = event.Records[0].s3.bucket.name;
    const key = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, ' '));
    const params = {
        Bucket: bucket,
        Key: key,
    };
    try {
        await s3.getObject(params, (err, data) => {
            if(!err) {
                console.log("Arquivo:");
                console.log(data.Body.toString());

                zlib.gzip(data.Body,(err, buffer) => {
                    if(err) {
                        console.log(err)
                    } else { 
                        console.log("gzip:");
                        console.log(buffer.toString('base64'));
                    }
                })

            }
        })        
        return 1;
    } catch (err) {
        console.log(err);
        const message = `Error getting object ${key} from bucket ${bucket}. Make sure they exist and your bucket is in the same region as this function.`;
        console.log(message);
        throw new Error(message);
    }
}