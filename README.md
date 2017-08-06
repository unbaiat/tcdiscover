# tcdiscover
Python script used to discover possible Truecrypt containers in DD images

Brief Description

TCDiscover is a python script that uses entropy calculations to find possible Truecrypt/encrypted containers on a .DD harddrive image.

The script will output the sector offset and the sector length to easily carve out the suspected container with a tool like dd.

We are fully aware that it is theoretically impossible to prove that a block of random-looking data is or is not a Truecrypt volume, short of decrypting it with the correct password. Our goal is to identify block sections that present reasonable suspicion of being Truecrypt containers by finding contiguous block runs of data where each block is over a certain entropy calculation.

For more information, please see: https://secure.wikimedia.org/wikipedia/en/wiki/TrueCrypt#Identifying_TrueCrypt_volumes

Usage:

``` Usage: ./tcdiscover.py -i

Usage: ./tcdiscover.py -d

optional flags: -e -s -b -c -o -l ```

Example output:

``` ./tcdiscover.py -i case1.dd

Searching for contiguous block runs in case1.dd with options: 
entropy limit: 7.0 minimum container size (bytes): 4194304 block size (bytes): 512 offset (blocks): 0 length after offset (blocks): 8388599

Potential TrueCrypt containers (units in blocks):

start:887151, len:21609
start:2360059, len:20400
start:3095287, len:25690
start:5639497, len:24420
start:6265969, len:20420
total time: 0:04:35.563749 ```
