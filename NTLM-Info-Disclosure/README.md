**DESCRIPTION**<br />
The following Nmap scripts anonymously enumerate remote NetBIOS, DNS, and OS details from various services with NTLM authentication enabled.  This is achieved by sending a NTLM Type 1 authentication request with null domain and user credentials to the remote service.  The service responds with a NTLMSSP encoded message and discloses NetBIOS, DNS, and OS build version information.

Utilizing this disclosed information is useful for network reconnaissance and may be used as part of more complex attacks, such as leveraging domain information for brute forcing accounts, identifying internal hostnames during external to internal pivoting activities, or determining end-of-life operating systems.

**SUPPORTED PROTOCOLS**<br />
The following protocols are supported:
- HTTP
- MS-SQL
- SMTP
- IMAP
- POP3
- NNTP
- Telnet

**INSTALLATION**<br />
Copy the scripts into the Nmap scripts folder.  In order to update the local script database, execute the following command as root/admin: 
```
$ sudo nmap --script-updatedb
```
After updating the local script database, since these scripts are classified as default/safe, they will run automatically when either the ‘-sC’ or ‘-A’ flags are utilized. If the script database is not updated, they will have to be declared via the command line in order to achieve execution.  

**USAGE**<br />
The example output below demonstrates how the script can be used against a HTTP service supporting NTLM authentication.  Similarly, information from other protocols supporting NTLM can be enumerated by defining the desired script.

```
$ nmap -p443 1.2.3.4 --script http-ntlm-info

Nmap scan report for 1.2.3.4
Host is up (0.040s latency).
PORT STATE SERVICE VERSION
443/tcp open https
| http-ntlm-info:
|  Target_Name: ACTIVEWEB
|  NetBIOS_Domain_Name: ACTIVEWEB
|  NetBIOS_Computer_Name: PRODWEB001
|  DNS_Domain_Name: activeweb.somedomain.com
|  DNS_Computer_Name: prodweb001.activeweb.somedomain.com
|  DNS_Tree_Name: activeweb.somedomain.com
|_ Product_Version: 5.2 (Build 3790)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**BLOG REFERENCES**<br />
http://blog.gdssecurity.com/labs/2014/2/12/http-ntlm-information-disclosure.html <br />
http://blog.gdssecurity.com/labs/2015/2/24/ntlm-information-disclosure-enhanced-protocol-support.html

**ADDITIONAL NOTES**<br />
The HTTP NTLM script (http-ntlm-info.nse) has been committed into the Nmap source.  All other scripts have been submitted and are awaiting commitment.
