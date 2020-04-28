#!/bin/bash

set -e

# remove untagged Docker images to avoid filling up the disk
sudo docker image prune -f
