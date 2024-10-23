# TryHackMe-Conti Ransomware

## Objective

This is a CTF challenge hosted on the website TryHackMe. This challenge involves using Splunk to investigate an Exchange server that was compromised by the Conti ransomware. The objective of this lab is to learn how the attackers compromised the server. On this page, I will document the steps and thought process I took to complete this challenge.

### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to spot common IOCs
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Splunk SIEM

## Overview:
Some employees from your company reported that they can’t log into Outlook. The Exchange system admin also reported that he can’t log in to the Exchange Admin Center. After initial triage, they discovered some weird readme files settled on the Exchange server.

<img src="https://github.com/user-attachments/assets/a7f73fd7-48cf-40db-b863-51177723ec53" alt="Note" width="700" />

### Question 1: Can you identify the location of the ransomware?
### Answer: C:\Users\Administrator\Documents\cmd.exe

For this first question, since we know that this ransomware has created a number of ReadMe.txt files, we can start by searching for event code 11, which is the file creation event code. We also know to look for this code based on question 2. By examining the important fields for this search, we can see that there are only 10 results in the image field. When looking into this image field, we can see that a cmd executable is located in a suspicious directory: C:\Users\Administrators\Documents\cmd.exe. When this was entered into the answer field, it was marked as correct.

<img src="https://github.com/user-attachments/assets/a38b9eef-4456-4416-9295-979db55773cc" alt="q2" width="900" />

### Question 2: What is the Sysmon event ID for the related file creation event?
### Answer: 11

The answer to this would be event code 11.

### Question 3: Can you find the MD5 hash of the ransomware?
### Answer: 290c7dfb01e50cea9e19da81a781af2c

To find this, I simply searched by the image file from question 1 and included the MD5 string, which yielded results containing the MD5 for the specified image file. The MD5 hash was 290c7dfb01e50cea9e19da81a781af2c, and after entering this hash into VirusTotal, it received over 60 malicious flags. Therefore, we can be certain that this is a malicious file.

<img src="https://github.com/user-attachments/assets/332a8a99-5df3-4b65-a21c-2e38ac37132b" alt="q3" width="700" />

### Question 4: What file was saved to multiple folder locations?
### Answer: readme.txt

By searching for the file creation event code related to the ransomware in our query, we can examine the TargetFileName field and see readme.txt stored in multiple locations.

<img src="https://github.com/user-attachments/assets/c5f9bd59-13cc-42ca-8815-9cebd232419f" alt="q4" width="700" />

### Question 5: What was the command the attacker used to add a new user to the compromised system?
### Answer: net user /add securityninja hardToHack123$

To find this answer we can search for any cases of the net user command in Splunk as it is the command line tool to create new users. After searching for this and looking under the CommandLine field we found the command that the attacker used.

<img src="https://github.com/user-attachments/assets/1f6b9343-2e2d-4726-b845-cdfbc13dc0ac" alt="q5" width="700" />

### Question 6: The attacker migrated the process for better persistence. What is the migrated process image (executable), and what is the original process image (executable) when the attacker got on the system?
### Answer: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Windows\System32\wbem\unsecapp.exe

For this question, I had to use a hint, as I knew I would most likely be searching by an event code, but I was unsure which event code I needed to search. The hint provided me with Sysmon event code 8, which is CreateRemoteThread. After some research, I found that this is used by malware to inject code and hide in another process. By searching for this event code, I found two logs, the first of which indicated that C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe migrated into C:\Windows\System32\wbem\unsecapp.exe. This is evident from the source image and target image fields.

<img src="https://github.com/user-attachments/assets/b0231e78-bd47-4e79-83d5-ed8599aacf63" alt="q6" width="700" />

### Question 7: The attacker also retrieved the system hashes. What is the process image used for getting the system hashes?
### Answer: C:\Windows\System32\lsass.exe

In the logs, I found that C:\Windows\System32\wbem\unsecapp.exe had migrated to C:\Windows\System32\lsass.exe. After some research, I realized that this process deals with authentication and authorization services for the system and handles hashes as well.

### Question 8: What is the web shell the exploit deployed to the system?
### Answer: i3gfPctK1c2x.aspx

For this problem, I searched for anything containing the .aspx extension, as this is a common web shell extension. One field that popped up was the cs_uri_stem field, which shows the path of the request made over HTTP or HTTPS. In this field, we can see a suspicious-looking file, which is our answer.

<img src="https://github.com/user-attachments/assets/b7906d86-60f1-484a-aee5-419e4008cd16" alt="q7" width="700" />

### Question 9: What is the command line that executed this web shell?
### Answer: attrib.exe  -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx

For this, I searched the CommandLine field for anything containing the malicious web shell. During my search, I found one log that had the answer.

<img src="https://github.com/user-attachments/assets/884d1f8c-c49a-4daf-9d60-3b7a3bacf52a" alt="q8" width="1000" /> <br>

<img src="https://github.com/user-attachments/assets/86e8d2ec-a6bb-4269-b218-716b18e9db44" alt="q8" width="900" />

### Question 10: What three CVEs did this exploit leverage?
### Answer: CVE-2020-0796,CVE-2018-13374,CVE-2018-13379

This question just required some research. After researching, I found a website that listed the vulnerabilities that the Conti ransomware uses.

### Conclusion

Overall, I felt that this lab challenged my Splunk, log analysis, problem-solving, and research skills. I completed this challenge a little while ago and now know that my Splunk queries and data presentation could have been better. I still learned a lot from this challenge and look forward to completing more in the future.
