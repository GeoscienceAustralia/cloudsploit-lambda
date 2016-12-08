#!/bin/bash

aws cloudformation update-stack --stack-name cloudsploit --template-body file://cloudsploit-stack.json --capabilities CAPABILITY_NAMED_IAM

stack_status="UPDATE_IN_PROGRESS"

while [ 1 ]; do

    response=$(aws cloudformation describe-stacks --stack-name cloudsploit 2>&1)
    responseOrig="$response"
    response=$(echo "$response" | tr '\n' ' ' | tr -s " " | sed -e 's/^ *//' -e 's/ *$//')

    if echo "$response" | egrep -q "StackStatus"
    then
        echo "Response contains StackStatus"
    else
        echo "Error occurred updating AWS CloudFormation stack. Error:"
        echo "$responseOrig"
        exit 1
    fi

    stack_status=$(echo $response | sed -e 's/^.*"StackStatus"[ ]*:[ ]*"//' -e 's/".*//')
    echo "StackStatus: $stack_status"

    if [ "$stack_status" = "ROLLBACK_IN_PROGRESS" ] || [ "$stack_status" = "ROLLBACK_COMPLETE" ] || [ "$stack_status" = "DELETE_IN_PROGRESS" ] || [ "$stack_status" = "DELETE_COMPLETE" ] || [ "$stack_status" = "UPDATE_ROLLBACK_IN_PROGRESS" ] || [ "$stack_status" = "UPDATE_ROLLBACK_COMPLETE " ]; then
        echo "Error occurred updating AWS CloudFormation stack and returned status code $stack_status. Details:"
        echo "$responseOrig"
        exit 1
    elif [ "$stack_status" = "UPDATE_COMPLETE" ] || [ "$stack_status" = "CREATE_COMPLETE" ]; then
        break
    fi

    # Sleep for 5 seconds, if stack update in progress
    sleep 5
done