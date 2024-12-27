# [Hammer](https://tryhackme.com/r/room/hammer)
> Use your exploitation skills to bypass authentication mechanisms on a website and get RCE

## Scanning

Start the machine and collect the "Target IP Address" to begin the scan.

![target](https://github.com/user-attachments/assets/4fbf364d-0821-4c10-a73d-d5901edc8fba)


Scan the IP using nmap 

```
sudo nmap -Pn -T4 -p1-10000 10.10.250.136 -vv -n
```

![image](https://github.com/user-attachments/assets/9a7a03a1-a5bd-4a4c-a672-f82950580ceb)

Two open ports are detected: port 22 and port 1337. Our primary focus will be thoroughly scanning port 1337.

```
sudo nmap -A -p1337 10.10.250.136 -vv -n
```

![image](https://github.com/user-attachments/assets/35d31347-3fdc-4666-be74-206653c7a68c)

We now know that port 1337 is running the HTTP protocol. Let's open the website using port 1337.

## HTTP

View the website. It appears to be a login page.

![image](https://github.com/user-attachments/assets/124b3b0c-9ee5-473b-995a-1410dfb8741f)

Inspect the page source to gather more information about the website.

![image](https://github.com/user-attachments/assets/d51ee046-c4b3-4412-bb9e-1f9cf48d6d17)

There's a developer note indicating that the directory naming convention starts with "hmr_(name)." For now, let's set this aside and continue searching for additional clues.

Click the "Forgot Your Password" button and inspect the page source for more clues.

![image](https://github.com/user-attachments/assets/db425a48-1137-4a2d-afa2-b03e16428992)
![image](https://github.com/user-attachments/assets/cc0fb13f-8956-4d81-abe3-5b31fe16dc64)

From the exposed backend code, we can determine that this site requires an OTP code to reset the password.

## Enumeration

Based on the information that the directory naming convention starts with "hmr_", let's enumerate and fuzz using Gobuster based on what we have gathered.

```
gobuster fuzz --url http://10.10.250.136:1337/hmr_FUZZ --wordlist /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -t 50 -b 404
```

![image](https://github.com/user-attachments/assets/5cb0d0f0-d33e-4cfc-bc77-1cf5dd06abe1)

One directory stands out: the "hmr_logs" directory. Let's navigate to the "hmr_logs" directory.

![image](https://github.com/user-attachments/assets/5022771c-9b61-410d-a055-649bfcf62b40)

Inside, open the "error.logs" file.

![image](https://github.com/user-attachments/assets/97aad702-f96a-49be-bc0b-f09b9c999e2c)

On line 3, there's an email address: tester@hammer.thm. This email can be used to reset its password by exploiting the OTP mechanism.

## Exploitation

![Screenshot 2024-12-27 142858](https://github.com/user-attachments/assets/91a3173f-9fd3-4e68-af23-a145fb597509)

![Screenshot 2024-12-27 142910](https://github.com/user-attachments/assets/1a0b7ccb-1d05-4dc6-923d-e62217a61d20)

![Screenshot 2024-12-27 143206](https://github.com/user-attachments/assets/dc71695f-2b0d-410c-8232-472a46c0bac3)

![Screenshot 2024-12-27 143234](https://github.com/user-attachments/assets/e9b9c829-f09d-4614-a688-a6368de4a780)

![Screenshot 2024-12-27 143525](https://github.com/user-attachments/assets/f2eee9f9-9a53-4afd-a455-2c714bb5dd5d)

![Screenshot 2024-12-27 143646](https://github.com/user-attachments/assets/77d98f39-a6ba-479a-856a-25828de0a525)

![Screenshot 2024-12-27 144621](https://github.com/user-attachments/assets/41373c04-a6b3-46b1-9559-5a98b5c73e5b)

![Screenshot 2024-12-27 144637](https://github.com/user-attachments/assets/ce3cfcf8-7f0f-4a93-a98b-42baede86993)

![Screenshot 2024-12-27 145456](https://github.com/user-attachments/assets/abe2edd4-199d-4bd6-a94e-25c1363f520b)

![Screenshot 2024-12-27 145340](https://github.com/user-attachments/assets/8f8efd4d-f4c8-4cc7-b456-b44472226861)

![Screenshot 2024-12-27 145554](https://github.com/user-attachments/assets/20a9c8e2-8113-4fc5-a151-cd5598e119c5)

![Screenshot 2024-12-27 145612](https://github.com/user-attachments/assets/ce57c68f-7dbe-4d9f-8ccd-7b13b74ab252)

![Screenshot 2024-12-27 145630](https://github.com/user-attachments/assets/3c68b862-dc58-4762-af39-0362a3cf3770)

![Screenshot 2024-12-27 150029](https://github.com/user-attachments/assets/9fac0ea4-27b1-488f-895a-c8723ba5284f)

## Privilage Escalation

![Screenshot 2024-12-27 150155](https://github.com/user-attachments/assets/05bcd6aa-aa7d-4c0d-8da0-fc506333eff9)

![Screenshot 2024-12-27 150318](https://github.com/user-attachments/assets/d94dd22c-9125-4ede-9889-66904306cd23)

![Screenshot 2024-12-27 150421](https://github.com/user-attachments/assets/ed2d43a6-5dac-4e6e-bf27-bf947ba6e185)

![Screenshot 2024-12-27 150051](https://github.com/user-attachments/assets/4de08c55-8d39-408b-b188-67712ff9e1f1)

![Screenshot 2024-12-27 150509](https://github.com/user-attachments/assets/0fa80781-7ca4-4019-b0e9-39c641d3f398)

![Screenshot 2024-12-27 150558](https://github.com/user-attachments/assets/121e52d6-22dc-41e0-bc2f-6975a798ae30)

![Screenshot 2024-12-27 150825](https://github.com/user-attachments/assets/3e8b3ab7-c81e-4f07-8764-317bf300ebfe)

![Screenshot 2024-12-27 150845](https://github.com/user-attachments/assets/4002435b-1e06-49b3-9f10-333b79e05c3d)

![Screenshot 2024-12-27 151046](https://github.com/user-attachments/assets/9ffbafbd-e3d4-44d1-a963-db384a776192)
