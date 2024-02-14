# Ivanti VPN Issues 2024 Jan-Feb

## CVE-2023-46805 and CVE-2024-21887 -  disclosed Wed, Jan 10

| Resource Type        | Link                                                                            | Notes |
| -------------------- | ------------------------------------------------------------------------------- | ----- |
| CVE                  | [CVE-2023-46805](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4680) | Authentication Bypass |
| CVE                  | [CVE-2024-21887](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21887) | Command Execution for Authn'd Admins | 
| Vendor KB Article    | [KB-2023-46805-and-2024-21887](https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways) | 
| Exploit              | [Metasploit module](http://packetstormsecurity.com/files/176668/Ivanti-Connect-Secure-Unauthenticated-Remote-Code-Execution.html) | Chains together CVE-2023-46805 and CVE-2024-21887 | 
| Blog Post            | [Ivanti Zero-day Vulnerabilities: CVE-2023-46805 & CVE-2024-21887](https://www.rapid7.com/blog/post/2024/01/11/etr-zero-day-exploitation-of-ivanti-connect-secure-and-policy-secure-gateways/) | Blog post by Caitlin Condon at Rapid7 |
| CISA Alert           | [Ivanti Releases Security Update for Connect Secure and Policy Secure Gateways](https://www.cisa.gov/news-events/alerts/2024/01/10/ivanti-releases-security-update-connect-secure-and-policy-secure-gateways) |CISA Alert 2024/01/10| 


## CVE-2024-21888 and CVE-2024-21893 - disclosed Wed, Jan 31

| Resource Type        | Link                                                                            | Notes |
| -------------------- | ------------------------------------------------------------------------------- | ----- |
| CVE                  | [CVE-2024-21888](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21888) | Privilege escalation in web interface from user to administrator | [KB-CVE-2024-21888-and-21893](https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) |
| CVE                  | [CVE-2024-21893](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21893) | SSRF allowing user-level access without authentication | 
| Vendor KB Article    | [KB-CVE-2024-21888-and-21893](https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) | |
| Press                | [Ivanti patches two zero-days under attack, but finds another](https://techcrunch.com/2024/01/31/ivanti-patches-two-zero-days-under-attack-but-finds-another/) | TechCrunch piece on third and fourth vulns |
| CISA Directive       | [CISA Supplemental Direction V1: ED 24-01: Mitigate Ivanti Connect Secure and Ivanti Policy Secure Vulnerabilities](https://www.cisa.gov/news-events/directives/supplemental-direction-v1-ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure) | CISA Supplemental Directive updated for third and fourth vulns |
| Press                | [All federal civilian agencies ordered to disconnect at-risk Ivanti products by Friday](https://therecord.media/federal-civilian-agencies-ordered-to-disconnect-at-risk-ivanti-products-cisa) | The Record by RecordedF Future News reporting on the CISA directive |



## CVE-2024-22024 - disclosed Friday 2/9/24

| Resource Type        | Link                                                                            | Notes |
| -------------------- | ------------------------------------------------------------------------------- | ----- |
| Vendor KB            |  [ CVE-2024-22024 (XXE) for Ivanti Connect Secure and Ivanti Policy Secure](https://forums.ivanti.com/s/article/CVE-2024-22024-XXE-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) | Ivanti Knowledge base article on fifth vulnerability |
| Exploit                 | [ Check for CVE-2024-22024 vulnerability in Ivanti Connect Secure](https://github.com/0dteam/CVE-2024-22024/blob/main/cve_2024_22024.py) | **unvetted** PoC for CVE-2024-22024 | 
| Press                | [ Ivanti: Patch new Connect Secure auth bypass bug immediately](https://www.bleepingcomputer.com/news/security/ivanti-patch-new-connect-secure-auth-bypass-bug-immediately/) | Bleeping Computer article on CVE-2024-22024 |
| Press                | [Ivanti discloses fifth vulnerability, doesn't credit researchers who found it](https://www.theregister.com/2024/02/09/ivanti_discloses_fifth_ics_vulnerability/) | Register article on fifth vulnerability |
| Discoverer     | [Ivanti Connect Secure CVE-2024-22024 - Are We Now Part Of Ivanti?](https://labs.watchtowr.com/are-we-now-part-of-ivanti/) | Watchtowr Labs article on discovering vuln |
| CVE                  | [CVE-2024-22024](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22024) | Authentication Bypass via XXE in SAML | 
| Press                | [Hackers exploit Ivanti SSRF flaw to deploy new DSLog backdoor](https://www.bleepingcomputer.com/news/security/hackers-exploit-ivanti-ssrf-flaw-to-deploy-new-dslog-backdoor/) | Press re using CVE-2024-22024 to install the DSLog backdoor | 
| Whitepaper / CERT Report | [Ivanti Connect Secure: Journey to the core of the DSLog backdoor](https://www.orangecyberdefense.com/fileadmin/general/pdf/Ivanti_Connect_Secure_-_Journey_to_the_core_of_the_DSLog_backdoor.pdf) | Orange Cyberdefense paper on DSLog backdoor |


## CVE and Vendor Knowledge Base Links by Vulnerability

| CVE Link | Type | Vendor KB |
| -------- | ---- | --------- |
|[CVE-2023-46805](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4680) | Authentication Bypass | [KB-2023-46805-and-2024-21887](https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways) | 
|[CVE-2024-21887](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21887) | Command Execution for Authn'd Admins | [KB-2023-46805-and-2024-21887](https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways) | 
|[CVE-2024-21888](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21888) | Privilege escalation in web interface from user to administrator | [KB-CVE-2024-21888-and-21893](https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) |
|[CVE-2024-21893](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21893) | SSRF allowing user-level access without authentication | [KB-CVE-2024-21888-and-21893](https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) |
|[CVE-2024-22024](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22024) | Authentication Bypass via XXE in SAML | [KB-CVE-2024-22024](https://forums.ivanti.com/s/article/CVE-2024-22024-XXE-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) |
