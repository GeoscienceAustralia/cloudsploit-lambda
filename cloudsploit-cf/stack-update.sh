#!/bin/bash

aws cloudformation update-stack --stack-name cloudsploit --template-body file://cloudsploit-stack.json --capabilities CAPABILITY_NAMED_IAM
