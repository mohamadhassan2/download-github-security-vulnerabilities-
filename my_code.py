import requests
from requests.auth import HTTPBasicAuth
import csv
import os
import zipfile
import json
import datetime
import time
from datetime import datetime, UTC, timezone

#Github authentication
username = "GIT_USER_NAME"
password = "GIT_PASSWORD"

# GitHub Advisory Database API URL
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"


# CISA Known Exploited Vulnerabilities (KEV) URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

#------------------------------------------------------------------------------
# Function to fetch vulnerabilities from GitHub Advisory Database
#https://www.w3schools.com/python/ref_requests_response.asp

def fetch_github_advisories():
    advisories = []
    page = 1

    while True:
        response = requests.get(f"{GITHUB_ADVISORY_URL}?page={page}")
        if response.status_code == 200:
            data = response.json()
            if not data:
                break
            advisories.extend(data)
            #print ("%2d" %  page)
            print(page, end=' ')
         #   print (f"Advisory data: {advisotries}")    #debug
            page += 1
        else:
            print (f"\033[42;30mFetched [{len(advisories)}] advisories\033[0m")
            print (f"\033[41;37mFailed to fetch advisories! Status code {response.status_code}\033[0m")
            print ("This is the call response text:")
            print ("---------------------------------")
            print (response.text)          #debug
            print ("---------------------------------")
            print ("-Try manual git authentication from cli (gh auth login --with-token < git_token.txt)")
            print ("-See: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28")
            print ("\n")
            break
    return advisories,response.status_code
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# Function to fetch the CISA Known Exploited Vulnerabilities (KEV) catalog
def fetch_kevs():
    response = requests.get(CISA_KEV_URL)
    if response.status_code == 200:
        kev_data = response.json()
        kev_ids = {entry['cveID'] for entry in kev_data.get('vulnerabilities', [])}
        print(f" \033[42;30mFetched [{len(kev_data)}] kev_data\033[0m", f"  \033[42;30m[{len(kev_ids)}] kev_ids\033[0m\n")
        #exit()
        return kev_ids
    else:
#        print(f"\033[41;37mFailed to fetch KEV data: {response.status_code}\033[0m")
        print(f"\n\033[41;37mFetched [{len(kev_data)}] KEVs. Failed to fetch CISA KEV data! Status code {response.status_code}\033[0m")
        return set()
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# Function to classify advisories by severity and zip them
def categorize_and_zip(advisories, kev_ids):

    #print (kev_ids)     #debug
    # Create folders for each severity category if not already created
    severities = ['low', 'moderate', 'high', 'critical']
    for severity in severities:
        if not os.path.exists(severity):
            os.makedirs(severity)

    # Initialize CSV data
    csv_data = []

    # Process advisories and zip them by severity
    for severity in severities:
        zip_filename = f"{severity}.zip"
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            for advisory in advisories:
                if advisory.get('severity') == severity:
                    # Create a CSV row with relevant fields
                    #cve_id = advisory.get('ghsaId', '')
                    cve_id = advisory.get('cve_id', '')

                    #if cve_id in kev_ids:
                    #    print ("FOUND")
                    #else:
                    #    print ("NOT FOUND")

                    csv_row = {
                        'CVE ID': cve_id,
                        'Severity': severity,
                        'Description': advisory.get('description', ''),
                        'Vulnerable Package': advisory.get('vulnerable_package', ''),
                        'Published At': advisory.get('published_at', ''),
                        'Updated At': advisory.get('updated_at', ''),
                        'KEV': '1' if cve_id in kev_ids else ''
                    }
                    csv_data.append(csv_row)

                    # Save advisory file (could be JSON or another format, simplified here)
                    advisory_filename = f"{severity}/{cve_id}.json"
                    with open(advisory_filename, 'w') as f:
                        json.dump(advisory, f)  # Store the advisory as JSON
                    zipf.write(advisory_filename)

    return csv_data
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# Function to generate the CSV file
def generate_csv(csv_data):
    fieldnames = ['CVE ID', 'Severity', 'Description', 'Vulnerable Package', 'Published At', 'Updated At', 'KEV']
    csv_filename = "vulnerabilities.csv"

    with open(csv_filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in csv_data:
            writer.writerow(row)

    #Count the lines in CSV file to see if has been populated
    with open(csv_filename, 'r') as fp:
        lines = len (fp.readlines()) - 1
    print(f"CSV file '{csv_filename}' has been created successfully! If fetching advisories failed then file will be empty [lines count:{lines}] \n")

'''
#------------------test
    try:
        with open('./critical/.json', 'r') as file:
            data = json.load(file)
            for v in data.values():
                print(f"CVE_ID: {data['cve_id']}")
                print(f"Severity: {data['severity']}")
                print(f"Description: {data['description']}")
                print(f"Vulnerable Package: {data['vulnerabilities'][0]['package']['name']}\n")
                print(f"Published At: {data['published_at']}")
                print(f"Uploaded At: {data['updated_at']}")
                print ("-----------------------------------\n")
    except FileNotFoundError:
        print("Error: 'critical/.json' not found.")
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in 'critical/.json'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
#------------------test
'''
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
def check_rate_limit(github_token=None):
    '''
    Checks the rate limit status for the GitHub API.
    Args:
        github_token (str, optional): Your GitHub personal access token.
        If not provided, it will attempt to read from the GITHUB_TOKEN environment variable.

    Returns:
        dict: A dictionary containing rate limit information, or None if an error occurs.
    '''
    if github_token is None:
        github_token = os.environ.get("GITHUB_TOKEN")
        if github_token is None:
            print("Error: GitHub token not found. Set GITHUB_TOKEN environment variable or pass it as an argument.")
            return None

    headers = {'Authorization': f'token {github_token}'}
    response = requests.get('https://api.github.com/rate_limit', headers=headers)

    if response.status_code == 200:
        return response.json()['resources']['core']
    else:
        print(f"\033[41;37mError: Failed to retrieve rate limit information. Status code: {response.status_code}\033[0m")
        return None

    #exit()
#------------------------------------------------------------------------------
def run_timer(timer_in_sec):
    print (f"\033[41;37mPrimary or Secondary GitHub API Rate Limit Reached. Results maybe incomplete!\033[0m")
    user_input = input(f"Wait {timer_in_sec} seconds [{timer_in_sec/60:.2f} mins] before re-running the fetch again (y/N)?")
    if user_input == "y" :
        print (f"Sleeping {timer_in_sec} seconds ...")
        time.sleep (timer_in_sec)
    return user_input
#------------------------------------------------------------------------------


# Main function to orchestrate the script
def main():

    #------------------------------------------
    #gh auth login --with-token < git_token.txt
    token = "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"
    headers = {'Authorization': f'token {token}'}
    response = requests.get('https://api.github.com/user', headers=headers)
    if response.status_code == 200:
        print(f"\033[94m>>GitHub Authentication successful!\n")
       # print(response.json())     #debug
    else:
        print(f"\033[41;37mGitHub Authentication failed. Status code: {response.status_code}\033[0m\n")
       # print(response.text)       #debug
    #------------------------------------------
    #Check API rate limits data  and calculate wait timer base on time difference------------
    print(f"\033[91m>>Fetching GitHub API Rate Limit Information...\033[0m")
    rate_limit = check_rate_limit("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")

    rate_limit_timestamp_epoc = (rate_limit['reset'])
    datetime_object_utc = datetime.fromtimestamp(rate_limit_timestamp_epoc)
    print(f"Limit:{rate_limit['limit']}\t ", f"Remaining in window:{rate_limit['remaining']}\t", f"Used:{rate_limit['used']}\t", f"Window will reset at:{datetime_object_utc}")

    curr_timestamp_epoc = int (time.time() )
    current_datetime = datetime.now()
    current_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

    print("Current Timestamp:\t", curr_timestamp_epoc, "\t\t", current_datetime )
    print("Rate Limit Timestamp:\t", rate_limit_timestamp_epoc, "\t\t", datetime.fromtimestamp(rate_limit_timestamp_epoc))
    #timer = int(( rate_limit_timestamp_epoc - curr_timestamp_epoc)/60 )
    timer_in_sec = (rate_limit_timestamp_epoc - curr_timestamp_epoc)
    print ("Timer in seconds:\t", timer_in_sec,"[",timer_in_sec/60,"mins]")
    #Check API rate limits data  and calculate wait timer base on time difference------------

    user_answer = "n"
    remaining = int (rate_limit['remaining'])   #convert set to int
    if (remaining > 0 ) or (curr_timestamp_epoc > rate_limit_timestamp_epoc) :
         user_answer = run_timer(timer_in_sec)

    print ("Starting....", user_answer)

    print("\033[92m>>Fetching GitHub Advisories Pages (may take time and subject to API rate limits)...\033[00m" )
    advisories, status_code = fetch_github_advisories()

    if (status_code != 200): # and (user_answer == "y"):
        user_answer = run_timer(timer_in_sec)
        print("\033[92m>>Fetching GitHub Advisories Pages (may take time and subject to API rate limits)...\033[00m", end="" )
        advisories, status_code = fetch_github_advisories()

    print(f"\033[93m>>Fetching CISA Known Exploited Vulnerabilities (KEV)...\033[00m", end="" )
    kev_ids = fetch_kevs()

    print("\033[94m>>Categorizing advisories by severity and zipping them...\033[00m \n")
    csv_data = categorize_and_zip(advisories, kev_ids)
    #print (csv_data)   #debug

    print("\033[95m>>Generating CSV file with vulnerability data..\033[00m \n")
    generate_csv(csv_data)

if __name__ == "__main__":
    main()
  
