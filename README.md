# download-github-security-vulnerabilities-
This python script will download all GitHub security vulnerabilities from the Github Advisory Database. 

__Problem statement:__  
The scrip will download all GitHUB security vulnerabilities from the Github Advisory Database: https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip. Then zips up the advisories by severity: 4 zips for each category of severity:  low, moderate, high, critical. The code will generate a csv file with a row for every vulnerability and a set of attributes summarizing the key information for each vulnerability. The CSV output contain a field called KEV. If the vulnerability is in the CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog-print , the KEV field value will be 1, Otherwise the field will be empty. 

__How to run:__  
1)Execute:   python mycode.py   (used python v3.12.3)  
2)You may encounter git API rate limitation:  
      Try creating a git token:(https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens). Add your token to a file (git_token.txt); then use the CLI to authenticate. Example: gh auth login --with-token < git_token.txt  
      

__Useful links:__  
https://www.w3schools.com/python/ref_requests_response.asp
https://www.endorlabs.com/learn/how-to-get-the-most-out-of-github-api-rate-limits
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#calculating-points-for-the-secondary-rate-limit
https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip

__Transparency Note:__  
The initial code was generated with chatGPT, however and as expected, few bugs and unintended logic was present. Additional logic (functions) is added to handle API rate limiting and retries, flow control and better user feedback during the execution.  
==========================================================================================================================================  

This is the inital code execution. If you have the correct GitHub token the first step of Authentication should succeed. Then we try to fetch any data on API rates. This should help us determine if we have any issues at this point (repeated testing tend to exhaust the calls). The sleep timer is created by calculating the difference between current time and the window reset time (returned from last call). I you answer "y" the program will sleep for the calculated timers:  

<img width="1040" alt="Screenshot 2025-03-21 at 5 41 39 PM" src="https://github.com/user-attachments/assets/7da1ae37-e1a8-4b07-b55e-ab1444efd1c7" />

