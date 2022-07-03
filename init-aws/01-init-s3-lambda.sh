#!/bin/bash
#
# Retirado de https://github.com/polovyivan/localstack-s3-events-to-sqs/blob/main/docker-compose/init-scripts/01-create-sqs.sh
#

echo "########### Setting up localstack profile ###########"
aws configure set aws_access_key_id access_key --profile=localstack
aws configure set aws_secret_access_key secret_key --profile=localstack
aws configure set region us-east-1 --profile=localstack

echo "########### Setting default profile ###########"
export AWS_DEFAULT_PROFILE=localstack

echo "########### Setting S3 name as env variables ###########"
export BUCKET_NAME=bucket-teste

echo "########### Create S3 bucket ###########"
aws --endpoint-url=http://localhost:4566 s3api create-bucket\
    --bucket $BUCKET_NAME --profile=localstack

echo "########### List S3 bucket ###########"
aws --endpoint-url=http://localhost:4566 s3api list-buckets

cd /tmp/lambda-spb-ts-src/dist
zip -r function.zip .


aws --endpoint-url=http://localhost:4566 \
    lambda create-function --function-name spb-lambda \
     --zip-file fileb:///tmp/lambda-spb-ts-src/dist/function.zip \
     --handler index.lambdaHandler --runtime nodejs12.x \
     --role arn:aws:iam::000000000000:role/lambda-role --profile=localstack



echo "########### Set S3 bucket notification configurations ###########"
aws --endpoint-url=http://localhost:4566 s3api put-bucket-notification-configuration\
    --bucket $BUCKET_NAME\
    --notification-configuration  '{
                                        "LambdaFunctionConfigurations": [
                                            {
                                                "Id": "s3eventtriggerslambda",
                                                "LambdaFunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:spb-lambda",
                                                "Events": ["s3:ObjectCreated:*"]
                                            }
                                        ]
                                    }'

echo "########### Get S3 bucket notification configurations ###########"
aws --endpoint-url=http://localhost:4566 s3api get-bucket-notification-configuration\
    --bucket $BUCKET_NAME
