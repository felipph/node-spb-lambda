# node-spb-lambda

## colocar Um arquivo no S3

```bash
 awslocal s3api put-object --bucket bucket-entrada --key req.gz.dat --body req.gz.dat

 awslocal s3 ls s3://bucket-bucket-saida --recursive --human-readable --summarize

 ```

Alguns links para ajuda:

```
https://aws.plainenglish.io/aws-lambda-testing-and-debugging-using-intellij-aws-sam-and-docker-f489f1d39b0d
https://aws.plainenglish.io/localstack-resource-creation-on-initialization-a86c2ce42310
```