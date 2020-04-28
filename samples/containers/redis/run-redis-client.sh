#!/bin/bash

# printf '\033]2;%s\033\\' 'Redis Client'

COUNTER=0

while :
do
  echo $ redis-cli -h 10.0.1.1 -p 6379 set samplekey value${COUNTER}
  redis-cli -h 10.0.1.1 -p 6379 set samplekey value${COUNTER}
  echo $ redis-cli -h 10.0.1.1 -p 6379 get samplekey
  redis-cli -h 10.0.1.1 -p 6379 get samplekey
  sleep 1
  let COUNTER+=1
done
