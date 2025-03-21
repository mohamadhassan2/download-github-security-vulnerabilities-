# download-github-security-vulnerabilities-
This python script will downloads all github security vulnerabilities from the Github Advisory Database. 

Problem statement:  
The scrip will download all github security vulnerabilities from the Github Advisory Database: https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip. Then zips up the advisories by severity: 4 zips for each category of severity:  low, moderate, high, critical. The code will generate a csv file with a row for every vulnerability and a set of attributes summarizing the key information for each vulnerability. The CSV output contain a field called KEV. If the vulnerability is in the CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print , the KEV field value will be 1, Otherwise the field will be empty. 

How to run:  
-Execute python mycode.py
-You may encounter git API rate limitation. To fix that try authenticating first. This can be done by populating the Git_USER_ID and GIT_PASSWORD in the code.  

-You can also try creating a git token, add to a file and use the CLI to authenticate from the cli (gh auth login --with-token < git_token.txt).  

Useful links:  
https://www.w3schools.com/python/ref_requests_response.asp
https://www.endorlabs.com/learn/how-to-get-the-most-out-of-github-api-rate-limits
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#calculating-points-for-the-secondary-rate-limit
https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip

