#!/bin/bash

##==============================================================================
##
## Check usage:
##
##==============================================================================

if [ "$#" -gt 1 ]; then
    echo "Usage: $0 <num-blocks>"
    exit 1
fi

if [ "$#" == 1 ]; then
    num_blocks=$1
else
    num_blocks=256
fi

##==============================================================================
##
## Generate an image file with random data
##
##==============================================================================

rm -f verity verity.hash
dd if=/dev/urandom of=verity bs=4096 count=${num_blocks} 2> /dev/null

##==============================================================================
##
## Run "veritysetup format" action
##
##==============================================================================

if [ -z "${BLKSZ}" ]; then
    BLKSZ=4096
fi

TMP=$(/bin/mktemp)

if ! veritysetup format --data-block-size="${BLKSZ}" --hash-block-size="${BLKSZ}" verity verity.hash > "${TMP}";
then
    echo "$0: *** veritysetup failed"
    exit 1
fi

root=$(grep "Root hash:" "${TMP}" | sed 's/Root hash:[\t ]*//g')
salt=$(grep "Salt:" "${TMP}" | sed 's/Salt:[\t ]*//g')
uuid=$(grep "UUID:" "${TMP}" | sed 's/UUID:[\t ]*//g')

#echo root=${root}
#echo uuid=${uuid}

##==============================================================================
##
## Run "vicsetup verityFormat" action
##
##==============================================================================

if ! vicsetup verityFormat --salt "${salt}" --uuid "${uuid}" --data-block-size="${BLKSZ}" --hash-block-size="${BLKSZ}" verity hashtree > /dev/null;
then
    echo "$0: *** vicsetup hashtree failed"
    exit 1
fi

##==============================================================================
##
## Verify that verity.hash and hashtree are idential
##
##==============================================================================

if ! cmp verity.hash hashtree;
then
    echo "$0: *** hash tree comparison failed"
    exit 1
fi

#rm -f verity verity.hash hashtree

echo "success"

##==============================================================================
##
## Attempt to open and close the verity device
##
##==============================================================================

dm_name=testverity
if ! vicsetup verityOpen verity "${dm_name}" hashtree "${root}";
then
    echo "$0: *** vicsetup verityOpen failed"
    exit 1
fi

TMP=$(/bin/mktemp)

dd if=/dev/mapper/"${dm_name}" of="${TMP}" > /dev/null 2> /dev/null
cmp "${TMP}" verity
rm "${TMP}"

vicsetup verityClose "${dm_name}"
