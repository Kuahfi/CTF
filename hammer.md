# [Hammer](https://tryhackme.com/r/room/hammer)
> Use your exploitation skills to bypass authentication mechanisms on a website and get RCE

## Scanning

Start the machine and collect the "Target IP Address" to scan.

!![target](https://github.com/user-attachments/assets/4fbf364d-0821-4c10-a73d-d5901edc8fba)


Scan the IP using nmap 

```
sudo nmap -Pn -T4 -p1-10000 10.10.250.136 -vv -n
```

!

We're getting 2 ports open, port 22 and 1337. Our main focus is to thoroughly scan the 1337 port.

```
sudo nmap -A -p1337 10.10.250.136 -vv -n
```

!

Now we knew that 1337 is a HTTP Protocol. So let's open up the website using 1337 port.

## HTTP

