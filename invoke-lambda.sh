#!/bin/bash

aws lambda invoke --function-name cloudsploitreporter outfile
rm outfile
