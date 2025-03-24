from xml.etree.ElementTree import tostring
import requests
from requests.auth import HTTPBasicAuth
import csv
import os
import zipfile
import json
import datetime
import time
from datetime import datetime, UTC, timezone
import logging
import signal
import sys
import shutil
import argparse

# GitHub Advisory Database API URL
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"


# CISA Known Exploited Vulnerabilities (KEV) URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

#------------------------------------------------------------------------------
# Function to fetch vulnerabilities from GitHub Advisory Database https://www.w3schools.com/python/ref_requests_response.asp
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
            print (f"\033[42;30mFetched [Pages:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}]\033[0m")
            logging.info (f"\033[42;30mFetched [Pages:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}]\033[0m")

            print (f"\033[41;37mFailed to fetch advisories! Status code {response.status_code}\033[0m")
            logging.warning (f"\033[41;37mFailed to fetch advisories! Status code {response.status_code}\033[0m")

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
        logging.info(f" \033[42;30mFetched [{len(kev_data)}] kev_data  [{len(kev_ids)}] kev_ids\033[0m")
        #exit()
        return kev_ids
    else:
#        print(f"\033[41;37mFailed to fetch KEV data: {response.status_code}\033[0m")
        print(f"\n\033[41;37mFetched [{len(kev_data)}] KEVs. Failed to fetch CISA KEV data! Status code {response.status_code}\033[0m")
        logging.warning(f"\n\033[41;37mFetched [{len(kev_data)}] KEVs. Failed to fetch CISA KEV data! Status code {response.status_code}\033[0m")
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
                    #--------------------------------------------------------------------------------------
                    directory_path = f"{severity}"
                 #   print ("Processing>> Directory path: ", directory_path, "  Advisory filename: ",advisory_filename)
                    #if os.path.exists(directory_path):
                    #    try:
                    #        shutil.rmtree(directory_path)
                    #        print(f"Directory '{directory_path}' and its contents deleted successfully.")
                    #        logging.info(f"Directory '{directory_path}' and its contents deleted successfully.")
                    #    except Exception as e:
                    #        print(f"Error deleting directory '{directory_path}': {e}")
                    #        logging.error (f"Error deleting directory '{directory_path}': {e}")
                    #else:
                    #    print(f"Directory '{directory_path}' does not exist.")
                    #    logging.warning (f"Directory '{directory_path}' does not exist.")
                    #--------------------------------------------------------------------------------------

                    with open(advisory_filename, 'w') as f:
                        json.dump(advisory, f)  # Store the advisory as JSON
                        logging.info (f"Dumping {advisory} as json into {advisory_filename}")

                    zipf.write(advisory_filename)
                    logging.info (f"Zipping into {advisory_filename}")

    return csv_data
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
def count_lines(output_file_name):

    #Count the lines in CSV file to see if has been populated
    with open(output_file_name, 'r') as fp:
        lines = len (fp.readlines()) - 1
    return lines
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# Function to generate the vuln CSV file
def generate_csv(csv_data, output_file_name):
    fieldnames = ['CVE ID', 'Severity', 'Description', 'Vulnerable Package', 'Published At', 'Updated At', 'KEV']
    csv_filename = output_file_name

    with open(csv_filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in csv_data:
            writer.writerow(row)

    lines = count_lines(csv_filename)

    if lines == 0:
        print(f"CSV file '{csv_filename}' has been created successfully! If fetching advisories failed in above step; then file will be empty! [\033[33;4mlines count:{lines}\033[0m] \n")
        logging.warning (f"CSV file '{csv_filename}' has been created successfully! If fetching advisories failed in above step; then file will be empty! [\033[33;4mlines count:{lines}\033[0m]")
    else:
        print(f"CSV file '{csv_filename}' created successfully! If fetching advisories failed in above step; then file will be empty [lines count:{lines}] \n")
        logging.info (f"CSV file '{csv_filename}' created successfully! If fetching advisories failed in above step; then file will be empty [lines count:{lines}]")

    return lines
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
#Function to check info for GitHUB rate limitations
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
            logging.error ("Error: GitHub token not found. Set GITHUB_TOKEN environment variable or pass it as an argument.")
            return None

    headers = {'Authorization': f'token {github_token}'}
    response = requests.get('https://api.github.com/rate_limit', headers=headers)

    if response.status_code == 200:
        return response.json()['resources']['core']
    else:
        print(f"\033[41;37mError: Failed to retrieve rate limit information. Status code: [\033[33;4m{response.status_code}]\033[0m")
        logging.error (f"\033[41;37mError: Failed to retrieve rate limit information. Status code: [\033[33;4m{response.status_code}]\033[0m")
        return None
#------------------------------------------------------------------------------
#Function to determine how long to pause between git api call (if you need to).
def run_timer(timer_in_sec):
    print (f"\033[41;37mPrimary or Secondary GitHub API Rate Limit Reached. Results maybe incomplete!\033[0m")
    logging.info (f"\033[41;37mPrimary or Secondary GitHub API Rate Limit Reached. Results maybe incomplete!\033[0m")
    user_input = input(f"Fetching appear to fail or incomplete. Want to try again with wait timer {timer_in_sec} seconds [{timer_in_sec/60:.2f} mins] (y/N)?")
    if user_input == "y" :
        print (f"Sleeping {timer_in_sec} seconds ...")
        logging.info (f"Sleeping {timer_in_sec} seconds ...")
        time.sleep (timer_in_sec)
    return user_input
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
def signal_handler(sig, frame):
    print('\nYou pressed Ctrl+C!')
    logging.warning ('You pressed Ctrl+C!')
    sys.exit(0)
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to authenticate to GitHub.
def authenticate_git():
    token_filename = "github_token.txt"
    if os.path.exists(token_filename):
        try:
            with open(token_filename, 'r') as file:
                first_line = file.readline()
                os.environ['GITHUB_TOKEN'] = first_line
                print("GitHub token file detected. Setting up the env var...")
                logging.info("GitHub token file detected. Setting up the env var...")
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print(f"File '{token_filename}' does not exist.")

    try:
        token = os.environ['GITHUB_TOKEN']
    except KeyError:
        while True:
            token = input(f"env GITHUB_TOKEN not set. Please set it in your shell (bash: export GITHUB_TOKEN=\"xxxxx\") or enter token now: ")
            if len (token) == 40 :
                print (f"Saving token to {token_filename} for further use")
                logging.INFO (f"Saving token to {token_filename} for further use")
                with open(token_filename, "w") as file:
                    file.write(token)
                break
            else:
                print (f"\n[{token}][{len(token)}] Must be at least 40 characters! Please re-enter:")


    headers = {'Authorization': f'token {token}'}
    response = requests.get('https://api.github.com/user', headers=headers)
    if response.status_code == 200:
        print(f"\033[94m>>GitHub Authentication successful!\033[0m\n")
        logging.info ("\033[94m>>GitHub Authentication successful!\033[0m")
       # print(response.json())     #debug
    else:
        print(f"\033[41;37mGitHub Authentication failed. Status code: [\033[33;4m{response.status_code}]\033[0m\n")
        logging.warning ("\033[41;37mGitHub Authentication failed. Status code: [\033[33;4m{response.status_code}]\033[0m\n")
       # print(response.text)       #debug
    return  token
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to setup python logging. Support all common types. This should be use to troubleshooting and debugging.
def setup_logging():
    #Setup logging
    logger = logging.getLogger(__name__)
    this_script_name = os.path.basename(__file__)
    logfile, extension = os.path.splitext(this_script_name)
    logfile += ".log"
    logging.basicConfig(format='%(asctime)s |%(levelname)s| %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', filename=logfile, encoding='utf-8', level=logging.DEBUG)
    #logger.debug('This message should go to the log file')
    logger.info('-----------------  STARTED  ---------\n')
    #logger.warning('And this, too')
    #logger.error('And non-ASCII stuff, too, like Øresund and Malmö')
    return
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to setup signal traps. We need to know when user hit CTRL-C
def setup_signal_handling():
    signal.signal(signal.SIGINT, signal_handler)
    #print('Press Ctl+C')
    #singal.pause()
    return
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------

# #------------------------------------------------------------------------------

# Main function to orchestrate the script
def main():

    this_script_name = os.path.basename(__file__)
    parser = argparse.ArgumentParser(prog=this_script_name, description='For details on this script see: https://github.com/mohamadhassan2/download-github-security-vulnerabilities-/blob/main/README.md ')

    parser.add_argument("-o", "--output_file", type=str, default='vulnerabilites', help="The output file name to save the results. [default: csv]", required=False )
    parser.add_argument('-t', '--type', type=str, default='csv', help="The output file type to save the results. Can be [json] or [csv:default]", required=False )      #option that takes a value
    parser.add_argument('-d', '--debug', default='False', action='store_true', help="Show extra debug information. [default: false]", required=False )   #on/off flag
    args = parser.parse_args()
    DEBUG = args.debug          #Used as global variable
    output_file_name = (args.output_file + "." + args.type)
    print(f"[Output_file: {output_file_name}]   [Type: {args.type}]   [Debug: {args.debug}]")
    print ("\n")

    x = setup_signal_handling()
    x = setup_logging()
    token = authenticate_git()

    #------------------------------------------
    #Check API rate limits data  and calculate wait timer base on time difference------------
    print(f"\033[91m>>Fetching GitHub API Rate Limit Information...\033[0m")
    logging.info (f"\033[91m>>Fetching GitHub API Rate Limit Information...\033[0m")
    rate_limit = check_rate_limit(token)

    rate_limit_timestamp_epoc = (rate_limit['reset'])
    datetime_object_utc = datetime.fromtimestamp(rate_limit_timestamp_epoc)
    #print(f"Limit:{rate_limit['limit']}\t ", f"Remaining in window:{rate_limit['remaining']}\t", f"Used:{rate_limit['used']}\t", f"Window will reset at:{datetime_object_utc}")
    print (f"API Rate Limting Data: [Limit:{rate_limit['limit']}]\t[Remaining in window:{rate_limit['remaining']}]\t[Used:{rate_limit['used']}]\t[Window will reset at:{datetime_object_utc}]")
    logging.info (f"API Rate Limting Data: [Limit:{rate_limit['limit']}][Remaining in window:{rate_limit['remaining']}][Used:{rate_limit['used']}][Window will reset at:{datetime_object_utc}]")

    curr_timestamp_epoc = int (time.time() )
    current_datetime = datetime.now()
    current_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

    print("Current Timestamp:\t", curr_timestamp_epoc, "\t\t", current_datetime )
    print("Rate Limit Timestamp:\t", rate_limit_timestamp_epoc, "\t\t", datetime.fromtimestamp(rate_limit_timestamp_epoc))
    #timer = int(( rate_limit_timestamp_epoc - curr_timestamp_epoc)/60 )
    timer_in_sec = (rate_limit_timestamp_epoc - curr_timestamp_epoc)
    print ("Timer in seconds:\t", timer_in_sec,"[", round(timer_in_sec/60,2), "mins]")
    #Check API rate limits data  and calculate wait timer base on time difference------------

#    timer_in_sec = 10   #debug
    user_answer = "n"
    remaining = int (rate_limit['remaining'])   #convert set to int
    if (remaining > 0 ) or (curr_timestamp_epoc > rate_limit_timestamp_epoc) :
         user_answer = run_timer(timer_in_sec)

    print ("Starting....", user_answer)

    print("\033[92m>>Fetching GitHub Advisories Pages (may take time and subject to API rate limits)...\033[00m" )
    logging.info ("\033[92m>>Fetching GitHub Advisories Pages (may take time and subject to API rate limits)...\033[00m" )
    advisories, status_code = fetch_github_advisories()

    if (status_code != 200) and (user_answer == "y"):
        user_answer = run_timer(timer_in_sec)
        print("\033[92m>>2nd Fetching GitHub Advisories Pages (may take time and subject to API rate limits)...\033[33;4m[Previous Status Code{status_code}]\033[00m", end="" )
        logging.info("\033[92m>>2nd Fetching GitHub Advisories Pages (may take time and subject to API rate limits)...[\033[33;4mPrevious Status Code {status_code}]\033[00m")
        advisories, status_code = fetch_github_advisories()
        print("\033[92m>>2nd Fetching GitHub Advisories Pages Result...\033[33;4m[Status Code {status_code}] \033[00m")
        logging.info ("\033[92m>>2nd Fetching GitHub Advisories Pages Result...[\033[33;5mStatus Code{status_code}]\033[00m")

    print(f"\033[93m>>Fetching CISA Known Exploited Vulnerabilities (KEV)...\033[00m", end="" )
    logging.info (f"\033[93m>>Fetching CISA Known Exploited Vulnerabilities (KEV)...\033[00m")
    kev_ids = fetch_kevs()

    print("\033[94m>>Categorizing advisories by severity and zipping them...\033[00m \n")
    logging.info ("\033[94m>>Categorizing advisories by severity and zipping them...\033[00m")
    csv_data = categorize_and_zip(advisories, kev_ids)
    #print (csv_data)   #debug

    print("\033[95m>>Generating CSV file with vulnerability data..\033[00m \n")
    logging.info ("\033[95m>>Generating CSV file with vulnerability data..\033[00m")
    lines = generate_csv(csv_data, output_file_name)
    if DEBUG:
        print ("csv_data:" , csv_data)

    lines = count_lines(output_file_name)
    print (f"------ FINISHED ----- Results: [Out FileName:{output_file_name} Len:{lines}] [CISA kev_ids:{len(kev_ids)}] [GitHub Advisories:{len(advisories)}]  ------\n ")
    logging.info (f"------ FINISHED ----- Results: [Out FileName:{output_file_name} Len:{lines}] [CISA kev_ids:{len(kev_ids)}] [GitHub Advisories:{len(advisories)}]  ------\n ")

if __name__ == "__main__":
    main()
