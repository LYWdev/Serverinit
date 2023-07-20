#!/bin/bash
rm /var/lib/apt/lists/lock
rm /var/cache/apt/archives/lock
rm /var/lib/dpkg/lock*
 dpkg --configure -a
 sudo apt update