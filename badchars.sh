#!/bin/bash
for i in $(seq 1 255); do
h=$(bc <<< "obase=16; $i")
if [ $i -gt 15 ]; then echo -n "\x$h"; else echo -n "\x0$h"; fi
done
echo
