#!/usr/bin/python
import re
import urllib2
import ssl
import json
import time
import whois
from datetime import datetime
# check how safe the adblockplus list is against google's SafeBrowsing API
# https://easylist-downloads.adblockplus.org/exceptionrules.txt
# rexex from https://stackoverflow.com/questions/21211572/extract-all-domains-from-text


def checkURLS(urls):
    # checks given list of URLs against googleapis; writes result to file
    client_id = "AdblockChecker"
    version = "0.1.3"
    api_key = "YOUR_GOOGLE_API_KEY"
    platform_types = ['ANY_PLATFORM']
    threat_types = ['THREAT_TYPE_UNSPECIFIED',
                'MALWARE','SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION']
    threat_entry_types = ['URL']
    apiurl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s' % (api_key)
    threat_entries = []
    for url_ in urls:
        url = {'url': url_}
        threat_entries.append(url)
    reqbody = {
        'client': {
            'clientId': client_id,
            'clientVersion': version
        },
        'threatInfo': {
            'threatTypes': threat_types,
            'platformTypes': platform_types,
            'threatEntryTypes': threat_entry_types,
            'threatEntries': threat_entries
        }
    }
    req = urllib2.Request(apiurl)
    req.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(req, json.dumps(reqbody)).read()
    print "[+] Writing to file"
    f = open('results.txt','a')
    f.write(response+'\n')
    f.close()

def checkAllSafeBrowsing(domains,SLEEP=5):
    # send domains in chunks of 500 to Google's safebrowsing API
    step=0
    for i in range(1,len(domains)):
        if i % 499 == 0:
            print "[+] Checking domains["+str(step)+":"+str(i)+"]"
            checkURLS(domains[step:i])
            step=i+1;
            time.sleep(SLEEP)
    #finish off the remaining domains
    print "[+] Checking domains["+str(step)+":"+str(len(domains))+"]"
    checkURLS(domains[step:len(domains)])


def readFile(filename):
    ### Naivley parse the exception rules and grab a list of domains
    # returns unique list of domains
    lines = []
    domains = []
    regex = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}'
    print "[+] Reading rules list"
    f = open(filename)
    for line in f:
        lines.append(line)
    f.close()
    print "[+] Parsing and adding domains"
    for d in lines:
        domains += re.findall(regex, d)
    print "[+] Removing duplicates"
    domainset = set(domains)
    domains = list(domainset)
    print "[+] Finished Parsing Stage"
    return domains;

def checkWhois(domains,SLEEP=1):
    f = open('domain_expires.txt','a')
    for d in domains:
        try:
            print "[+] Checking domain: "+d
            now = datetime.now()
            w = whois.whois(d)
            w.expiration_date = w.expiration_date[0] if type(w.expiration_date) == list else w.expiration_date
            domain_expiration_date = str(w.expiration_date.day) + '/' + str(w.expiration_date.month) + '/' + str(w.expiration_date.year)
            timedelta = w.expiration_date - now
            f.write(d+':'+str(timedelta.days)+'\n')
            time.sleep(SLEEP)
        except Exception as e:
            # ain't nobody got time for that
            # grep out all the errors afterwards and run again
            print "[-] Something went wrong with: "+d
            f.write(d+': Error!\n')
            continue
    f.close()

domains = readFile("exceptionrules.txt")
checkAllSafeBrowsing(domains);
#checkWhois(domains)
