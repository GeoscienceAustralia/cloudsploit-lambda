#!/bin/bash

cd cloudsploit-report/
zip -r handler.zip *
aws s3 cp handler.zip s3://cloudsploit/cloudsploit-report.zip --acl public-read
rm handler.zip outfile

