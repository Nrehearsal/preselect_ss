#!/bin/bash

cd ./src
gcc *.c -lev -lsodium -lmbedcrypto -ljson-c -lm -o ../preselect_ss
