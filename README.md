linux-netns-hops
======================
A silly script to generate a "traceroute" from text within a file.

Outputs a shell script with the required iproute2 and sysctl commands to create hops between namespaces under linux. One hop per line within the input text file.
This script will also generate PTR records in a seperate file for inclusion in an authoritative BIND name server for the IP prefix(es) used as inputs to this script.


**Usage:** linux-netns-hops.py [-h] [-4 IPV4] [-6 IPV6] -f FILE

Example usage:
```
./linux-netns-hops.py -f traceroute.txt -6 "2607:ffc8:8000:fa57::/64"
```
