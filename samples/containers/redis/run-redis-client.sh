#!/bin/bash

# printf '\033]2;%s\033\\' 'Redis Client'

set -e

COUNTER=0

while [ $COUNTER -lt 10 ]
do
  echo $ redis-cli -h 10.0.1.1 -p 6379 set samplekey value${COUNTER}
  redis-cli -h 10.0.1.1 -p 6379 set samplekey value${COUNTER}
  echo $ redis-cli -h 10.0.1.1 -p 6379 get samplekey
  redis-cli -h 10.0.1.1 -p 6379 get samplekey
  let COUNTER+=1
done

echo "Sample succeeded"
