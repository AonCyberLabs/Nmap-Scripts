nmap-scripts
============
The Nmap scripts, located in the NTLM-Info-Disclosure directory, anonymously enumerate remote NetBIOS, DNS, and OS details from various services with NTLM authentication enabled. This is achieved by sending a NTLM Type 1 authentication request with null domain and user credentials to the remote service. The service responds with a NTLMSSP encoded message and discloses NetBIOS, DNS, and OS build version information.

Utilizing this disclosed information is useful for network reconnaissance and may be used as part of more complex attacks, such as leveraging domain information for brute forcing accounts, identifying internal hostnames during external to internal pivoting activities, or determining end-of-life operating systems.
