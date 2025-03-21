# download-github-security-vulnerabilities-
This python script will download all GitHub security vulnerabilities from the Github Advisory Database. 

__Problem statement:__  
The scrip will download all GitHUB security vulnerabilities from the Github Advisory Database: https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip. Then zips up the advisories by severity: 4 zips for each category of severity:  low, moderate, high, critical. The code will generate a csv file with a row for every vulnerability and a set of attributes summarizing the key information for each vulnerability. The CSV output contain a field called KEV. If the vulnerability is in the CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print , the KEV field value will be 1, Otherwise the field will be empty. 

__How to run:__  
1)Execute python mycode.py  

2)You may encounter git API rate limitation. To fix this; try authenticating first. This can be done by populating the Git_USER_ID and GIT_PASSWORD in the code. A more secure way would be to read those values using environmenal variables.  

-You can also try creating a git token:(https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens), add to a file and use the CLI to authenticate from the cli (gh auth login --with-token < git_token.txt).  

__Useful links:__  
https://www.w3schools.com/python/ref_requests_response.asp
https://www.endorlabs.com/learn/how-to-get-the-most-out-of-github-api-rate-limits
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#calculating-points-for-the-secondary-rate-limit
https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip

__Transparency Note:__  
The initial code was generated with chatGPT, however and as expected, few bugs and unintended logic was present. Additional logic (functions) is added to handle API rate limiting and retries, flow control and better user feedback during the execution.  
