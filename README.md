# SafeBrowsingCheck
Checks a given file for all domains against the Google SafeBrowsing API. 
### Dependencies
Only for further domain expirey checks:
- python-whois 
### Usage
Download the latest exception list and save it: `wget "https://easylist-downloads.adblockplus.org/exceptionrules.txt" -O exceptionrules.txt`   
Run the SafeBrowsing Check: `python checker.py`   
Check `results.txt` for output

#### Example

```sh 
$ python checker.py 
[+] Reading rules list
[+] Parsing and adding domains
[+] Removing duplicates
[+] Finished Parsing Stage
[+] Checking domains[0:499]
[+] Writing to file
[+] Checking domains[500:998]
[+] Writing to file
```
