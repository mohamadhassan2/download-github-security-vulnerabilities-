# download-github-security-vulnerabilities-
This python script will downloads all github security vulnerabilities from the Github Advisory Database. 
Problem statement:
The scrip will download all github security vulnerabilities from the Github Advisory Database:. Then zips up the advisories by severity: 4 zips for each category of severity:  low, moderate, high, critical. The code will generate a csv file with a row for every vulnerability and a set of attributes summarizing the key information for each vulnerability. The CSV output contain a field called KEV. If the vulnerability is in the CISA Known Exploited Vulnerabilities Catalog, the KEV field value will be 1, Otherwise the field will be empty. 
