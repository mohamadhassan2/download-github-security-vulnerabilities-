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
import subprocess       #to execute cli commands

import warnings
warnings.filterwarnings("ignore", message="Duplicate name*", module="zipfile")  #suppress warning when re-creating existing dir/filename


# GitHub Advisory Database API URL
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"

# CISA Known Exploited Vulnerabilities (KEV) URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

#------------------------------------------------------------------------------
#Function to fetch (as one shot) the CISA Known Exploited Vulnerabilities (KEV) catalog
#Inputs:    None
#Outputs:   kev_ids{}: set
def fetch_kevs():
    print(f"➡️ \033[93m>>Fetching CISA Known Exploited Vulnerabilities (KEV)...\033[00m", end="" )
    logging.info (f"➡️ \033[93m>>Fetching CISA Known Exploited Vulnerabilities (KEV)...\033[00m")

    response = requests.get(CISA_KEV_URL)
    if response.status_code == 200:
        kev_data = response.json()
        kev_ids = {entry['cveID'] for entry in kev_data.get('vulnerabilities', [])}
        print(f"👍 \033[42;30mFetched [{len(kev_data)}] kev_data\033[0m", f"  \033[42;30m[{len(kev_ids)}] kev_ids\033[0m\n")
        logging.info(f" \033[42;30mFetched [{len(kev_data)}] kev_data  [{len(kev_ids)}] kev_ids\033[0m")
        #exit()
        return kev_ids
    else:
#        print(f"\033[41;37mFailed to fetch KEV data: {response.status_code}\033[0m")
        print(f"\n⚠️ \033[41;37mFetched [{len(kev_data)}] KEVs. Failed to fetch CISA KEV data! Status code {response.status_code}\033[0m")
        logging.warning(f"\n⚠️ \033[41;37mFetched [{len(kev_data)}] KEVs. Failed to fetch CISA KEV data! Status code {response.status_code}\033[0m")
        return set()

#end of fetch_kevs():
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
def progressBar(iterable, page, status , prefix = '', suffix = '', decimals = 1, length = 100, fill = '#', printEnd = "\r"):
    #print (iterable, "  ", len(iterable))
    #exit()
    """
    https://stackoverflow.com/questions/3173320/text-progress-bar-in-terminal-with-block-characters
    Call in a loop to create terminal progress bar
    @params:
        iterable    - Required  : iterable object (Iterable)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    total = len(iterable)
    # Progress Bar Printing Function
    def printProgressBar (iteration):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{prefix}[page:{page}] |{bar}| {percent}% {suffix}    [status:{status}]', end = printEnd)
    # Initial Call
    printProgressBar(0)
    # Update Progress Bar
    for i, item in enumerate(iterable):
        yield item
        printProgressBar(i + 1)
    # Print New Line on Complete
    print()
#End of progressBar(iterable, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to fetch (by page) vulnerabilities from GitHub Advisory Database https://www.w3schools.com/python/ref_requests_response.asp
#Inputs:    None
#Outputs:   advisories : List
#           status_code: int result of the call
def fetch_github_advisories():
    advisories = []
    page = 0
    print("➡️ \033[92m>>Fetching GitHub Advisories Pages (may take time and subject to API rate limits)...\033[00m" )
    logging.info ("➡️ \033[92m>>Fetching GitHub Advisories Pages (may take time and subject to API rate limits)...\033[00m" )

    while True:         #loop by page. Break if data=empty or status !=200
        page_size = 50
        response = requests.get(f"{GITHUB_ADVISORY_URL}?page={page}?page_size={page_size}")       #method 1
        #response = requests.get(f"{GITHUB_ADVISORY_URL}?page={page}?bearer='ghp_lY3WIDWXXXXXXXXXXXX'")    #method 2

        if response.status_code == 200:
            data = response.json()          #get elements in a page
            if not data:
                break

            advisories.extend(data)         #add multiple elements to the end of a list
            #print ("%2d" %  page)
            #print(page)#, end=' ')    #show page number fetched, prints after the entire data is retrieved

            #if type(DEBUG) is bool:
            if DEBUG != 0 :
                print (f"\033[36m🐞DEBUG[{DEBUG}]: fetch_github_advisories(). Page:[{page}]\033[0m")
                #cve_ids = {entry['cve_id'] for entry in advisories[-30]}
                #print (f"one record:[{pretty_json}]")

                for record in data:
                    page += 1
                    cveID = record['cve_id']
                    match DEBUG:
                        case 1:
                            print (f" \033[35m[Page:{page} Record Len:{len(record)} Status:{response.status_code} CVE:{cveID}] \033[0m")
                        case 2:
                            print (record, f" \033[35m[Page:{page} Record Len:{len(record)} Status:{response.status_code} CVE:{cveID}] \033[0m")
                        case 3:
                            pretty_json = json.dumps(record, indent=4)
                            print(pretty_json)
                            print (pretty_json, f" \033[35m[Page:{page} Record Len:{len(record)} Status:{response.status_code} CVE:{cveID}] \033[0m")
                        case 4:
                            print (advisories, f" \033[35m[Page:{page} Advisories Len:{len(advisories)} Status:{response.status_code} CVE:{cveID}] \033[0m")
                        case 5:
                            items = record              # A List of Items
                            status = response.status_code
                            #print (items)
                            #exit()
                            # A Nicer, Single-Call Usage
                            for item in progressBar(items, page, status, prefix = 'Retrieving', suffix = 'Complete', length = 10):
                                # Do stuff...
                                time.sleep(0.0001)

            #print (f"👍 \tResults: [Pages:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}]\033[0m")
            #logging.info (f"👍 Results: Pges:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}]\033[0m")
        else:


            print ("\n🚥 This is the request.get() returned text:")
            print ("------------------------------------------------------------")
            print (f"=>[\033[91m",{response.text},"\033[0m]<=" )          #debug
            print ("------------------------------------------------------------")
            print (f"👉 Try git authentication from cli then re-run the scipt (gh auth login --with-token < {GITHUB_TOKEN_FILE})")
            print ("👉 See: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28\n")
            break
        #print("\n")
    #end loop
    if len(advisories) == 0:
        print (f"👎 \033[35m[Pages:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}] ->:The initial call failed too quickly. An indication of reaching API rate limit! Recommend using pause timer.\033[0m")
        logging.warning (f"👎 \033[35m[Pages:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}] ->:The intial call failed too quickly. An indication of reaching API rate limit!]\033[0m]")
    else:
        print (f"🤷‍♀️ \033[35m[Pages:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}] ->:Some pages fetched, but wrong status code. An indication of reaching rate limit or end of data.\033[0m]")
        logging.warning (f"🤷‍♀️ \033[35m[Pages:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}] ->:Some pages fetched, but wrong status code. An indication of reaching rate limit or end-of-data.\033[0m]")

    #print (f"Results: Fetched [Pages:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}]\033[0m")
    #logging.info (f"Results: Fetched [Pages:{page}] [Advisories:{len(advisories)}] [Status Code:{response.status_code}]\033[0m")
    return advisories,response.status_code

#end of fetch_github_advisories():
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to classify advisories by severity and zip them. Store the advisory as JSON file (in dir named severity)
#Inputs:    advisories[]: list
#           kev_ids{}: set
#Outputs:   csv_data[]: list
def categorize_and_zip(advisories, kev_ids):
    print("➡️ \033[94m>>Categorizing advisories by severity and zipping them...\033[00m \n")
    logging.info ("➡️ \033[94m>>Categorizing advisories by severity and zipping them...\033[00m")

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


    #print(f"kev_ids:",type(kev_ids),"  advisoris:", type(advisories), "  csv_data:", type(csv_data))
    #exit()
    return csv_data

#end of categorize_and_zip(advisories, kev_ids):
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to count the lines in CSV file to see if has been populated
def count_lines(output_file_name):


    with open(output_file_name, 'r') as fp:
        lines = len (fp.readlines()) - 1
    return lines
#end of count_lines()
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to generate the vuln CSV/JSON file
#Inputs:        csv_data[]: list
#               output_file_name: Name of the csv/json vuln out file as set by returned args or defaults.
#Outputs:       lines: int number of lines in csv out file
def generate_csv(csv_data, output_file_name):
    print("➡️ \033[95m>>Generating CSV file with vulnerability data..\033[00m \n")
    logging.info ("➡️ \033[95m>>Generating CSV file with vulnerability data..\033[00m")

    fieldnames = ['CVE ID', 'Severity', 'Description', 'Vulnerable Package', 'Published At', 'Updated At', 'KEV']
    csv_filename = output_file_name

    row_no = 0
    with open(csv_filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in csv_data:
            writer.writerow(row)
            row_no = row_no + 1
            match DEBUG:
                case 1:
                    print (f"\033[36m🐞 DEBUG{DEBUG}: generate_csv(): Writting Row:{row_no}\033[0m\n")
                case 3:
                    print (f"\033[36m🐞 DEBUG{DEBUG}: generate_csv(): Writting Row:{row_no}>>\033[0m <<\n" ,row)

    lines = count_lines(csv_filename)

    if lines == 0:
        print(f"⚠️ CSV file '{csv_filename}' has been created, but the file appears to be empty! [\033[33;4mlines count:{lines}\033[0m] \n")
        logging.warning (f"⚠️ CSV file '{csv_filename}' has been created, but the file appears to be empty! [\033[33;4mlines count:{lines}\033[0m]")
    else:
        print(f"    🟢 CSV file '{csv_filename}' created successfully...👍 \033[42;30m[lines count:{lines}]\033[0m\n")
        logging.info (f"🟢 CSV file '{csv_filename}' created successfully...👍 \033[42;30m[lines count:{lines}]\033[0m\n")

    match DEBUG:
        case 1:
            print (f"\033[36m🐞DEBUG{DEBUG}: main(). csv_data:>>\033[0m]" , csv_data, "<<")

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
#end of generate_csv(csv_data, output_file_name):
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
def signal_handler(sig, frame):
    print('\nYou pressed Ctrl+C!')
    logging.warning ('You pressed Ctrl+C!')
    sys.exit(0)
#end of signal_handler(sig, frame):
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to authenticate to GitHub. First will attempt to read the token the env. If found
# will save to text file for further usage. If not found; prompt user
#Inputs:    none
#Outputs:   40 char token and set the env GITHUB_TOKEN
def authenticate_git():
    token_filename = GITHUB_TOKEN_FILE
    if os.path.exists(token_filename):
        try:
            with open(token_filename, 'r') as file:
                first_line = file.readline()
                os.environ['GITHUB_TOKEN'] = first_line
                print("GitHub token file detected. Setting up the environmental variable $GITHUB_TOKEN...")
                logging.info("GitHub token file detected. Setting up the environmental variable $GITHUB_TOKEN...")
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

    #Some time cli authentication works better to reset api rate limits, so we are trying both methods
    #---authentication method 1 -------
    result = subprocess.run(['echo', '{token}', '|', 'gh', 'auth', 'login', '--with-token'], capture_output=True, text=True, shell=True)
    #result = subprocess.run(['ls', '-l'], capture_output=True, text=True)
    # Check if the command was successful
    if result.returncode == 0:
        print("CLI GitHub authentication. Command executed successfully:")
        print(result.stdout)
    else:
        print(f"CLI GitHub authentication. Command failed with error code {result.returncode}:")
        print(result.stderr)

    #---authentication method 2 -------
    headers = {'Authorization': f'token {token}'}
    response = requests.get('https://api.github.com/user', headers=headers)
    if response.status_code == 200:
        print(f"🟢 \033[94m>>GitHub Authentication successful!\033[0m\n")
        logging.info ("🟢 \033[94m>>GitHub Authentication successful!\033[0m")
       # print(response.json())     #debug
    else:
        print(f"⛔️ \033[41;37mGitHub Authentication failed. Status code: [\033[33;4m{response.status_code}]\033[0m\n")
        logging.warning ("\033[41;37mGitHub Authentication failed. Status code: [\033[33;4m{response.status_code}]\033[0m\n")
       # print(response.text)       #debug


    return  token
#end of authenticate_git():
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
    logger.info('-----------------  STARTED  ---------\n')
    #logger.warning('And this, too')
    #logger.error('And non-ASCII stuff, too, like Øresund and Malmö')
    return
#end of setup_logging():
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to setup signal traps. We need to know when user hit CTRL-C
def setup_signal_handling():
    signal.signal(signal.SIGINT, signal_handler)
    #print('Press Ctl+C')
    #singal.pause()
    return
#end of setup_signal_handling():
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#This code snippet utilizes the sys.stdout.write and sys.stdout.flush methods to overwrite the previous
#timer value on the same line, creating the effect of a live countdown. The \r character moves the cursor
#to the beginning of the line before writing the new timer value.
def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '\033[36m{:02d}:{:02d}'.format(mins, secs)
        sys.stdout.write('\r' + timer)
        sys.stdout.flush()
        time.sleep(1)
        t -= 1
    print("  Done!\033[0m\n")
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to determine how long to pause between git api call (if you need to).
def ask_to_run_timer(timer_in_sec):

    user_input = input(f"Want to pause (calcuated) for \033[36m{timer_in_sec/60:.2f} mins \033[0m[{timer_in_sec} sec] before trying again (y/N)?")
    if user_input == "y" :
        print(f"Yes")
        print (f"Sleeping [{timer_in_sec/60:.2f}] mins...")
        logging.info (f"Sleeping [{timer_in_sec/60:.2f}] mins...")
        #time.sleep (timer_in_sec)
        countdown(int(timer_in_sec))
    else:
        print(f"No")    #don't run timer
    print("\n")

    return user_input

#end of ask_to_run_timer(timer_in_sec):
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#Function to Checks the rate limit status for the GitHub API.
#Check API rate limits data  and calculate wait timer base on time difference------------
# Args:
#        github_token (str, optional): Your GitHub personal access token.
#        If not provided, it will attempt to read from the GITHUB_TOKEN environment variable.
#Returns:
#        dict: A dictionary containing rate limit information, or None if an error occurs.
#
def check_rate_limit(github_token=None):
    print(f"➡️ \033[94m>>Getting GitHub API Rate Limit Information...\033[0m")
    logging.info (f"➡️ \033[94m>>Getting GitHub API Rate Limit Information...\033[0m")

    if github_token is None:
        github_token = os.environ.get("GITHUB_TOKEN")
        if github_token is None:
            print("⛔️ Error: GitHub token not found. Set GITHUB_TOKEN environment variable or pass it as an argument.")
            logging.error ("⛔️ Error: GitHub token not found. Set GITHUB_TOKEN environment variable or pass it as an argument.")
            return None

    headers = {'Authorization': f'token {github_token}'}
    response = requests.get('https://api.github.com/rate_limit', headers=headers)

    if response.status_code == 200:
        return response.json()['resources']['core']
    else:
        print(f"⛔️ \033[41;37mError: Failed to retrieve rate limit information. Status code: [\033[33;4m{response.status_code}]\033[0m")
        logging.error (f"⛔️ \033[41;37mError: Failed to retrieve rate limit information. Status code: [\033[33;4m{response.status_code}]\033[0m")
        return None
#end of check_rate_limit(github_token=None):
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
def calculate_pause_timer(rate_limit):

    rate_limit_timestamp_epoc = (rate_limit['reset'])
    datetime_object_utc = datetime.fromtimestamp(rate_limit_timestamp_epoc)

    print (f"API Rate Limting Data: [Limit:{rate_limit['limit']}]\t[Remaining in window:{rate_limit['remaining']}]\t[Used:{rate_limit['used']}]\t[Window will reset at:{datetime_object_utc}]")
    logging.info (f"API Rate Limting Data: [Limit:{rate_limit['limit']}][Remaining in window:{rate_limit['remaining']}][Used:{rate_limit['used']}][Window will reset at:{datetime_object_utc}]")

    curr_timestamp_epoc = int (time.time() )
    current_datetime = datetime.now()
    current_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
    print("Current Timestamp:\t", curr_timestamp_epoc, "\t\t", current_datetime )
    print("Rate Limit Timestamp:\t", rate_limit_timestamp_epoc, "\t\t", datetime.fromtimestamp(rate_limit_timestamp_epoc))
    #timer = int(( rate_limit_timestamp_epoc - curr_timestamp_epoc)/60 )
    timer_in_sec = (rate_limit_timestamp_epoc - curr_timestamp_epoc)
    print ("Calculated ideal pause (in seconds):\t\t", timer_in_sec,"[", round(timer_in_sec/60,2), "mins]")

    #pause_in_sec = 10   #debug
    answer = "n"        #default not to pause
    remaining = int (rate_limit['remaining'])   #convert set to int
    if (remaining < 1 ) or (curr_timestamp_epoc > rate_limit_timestamp_epoc) :
        answer = ask_to_run_timer(timer_in_sec)
        print ("You answerd: [", answer,"]")

    return timer_in_sec, answer

#end calculate_pause_timer():
#------------------------------------------------------------------------------

#==============================================================================
# Main function to orchestrate the script
def main():
    global DEBUG
    global GITHUB_TOKEN_FILE
    GITHUB_TOKEN_FILE = "github_token.txt"

    #os.system('cls' if os.name == 'nt' else 'clear')        #clear screen
    #----------------get args from user------------------------
    this_script_name = os.path.basename(__file__)
    parser = argparse.ArgumentParser(prog=this_script_name, \
                                    description='For details on this script see: https://github.com/mohamadhassan2/download-github-security-vulnerabilities-/blob/main/README.md ')
    parser.add_argument("-o", "--output_file", type=str, default='vulnerabilites', \
                        help="The output file name to save the results. [default: csv]", required=False )
    parser.add_argument('-t', '--type', type=str, default='csv', \
                        help="Set the type (ie ext) of the output file. Can be [json] or [csv:default]", required=False )      #option that takes a value
    parser.add_argument('-d', '--debug', type=int, default='0', \
                        help="Set debug level number [0:none(default) 1:low 2:medium 3:high]]", required=False )

    args = parser.parse_args()
    DEBUG = args.debug
    output_file_name = (args.output_file + "." + args.type)
    #print(f"[Output_file:{output_file_name}]   [Type:{args.type}]   [Debug Level:{DEBUG}]")   #debug

    print ("\n")
    #----------------get args from user------------------------

    x = setup_signal_handling()
    x = setup_logging()
    token = authenticate_git()          #get token from user or env or text file

    rate_limit = check_rate_limit(token)    #use token to find rate limits data (dic: rate_limit)

    pause_in_sec, answer = calculate_pause_timer(rate_limit)

    start_datetime = datetime.now()
    print (f"\n\t\t----------------- STARTED @ {start_datetime} ----------------\n")

    advisories, last_status_code = fetch_github_advisories()

    if (last_status_code != 200) and (len(advisories) > 0 ):
        print (f"\n🟡 Retrieved some advisories pages, but the return status code was not 200. Data may be incomplete!\033[0m\n")


    if (last_status_code != 200):
        print (f"\nℹ️  Based on retrieved GitHub-API-Rate-limits, you may have reached the Primary or Secondary limit!\033[0m\n")
        logging.info (f"ℹ️  Based on retrieved GitHub-API-Rate-limits, you may have reached the Primary or Secondary limit!\033[0m")

        answer = ask_to_run_timer(pause_in_sec)
        if answer == 'y':
            print("🟡 \033[92m>>Fetching GitHub Advisories Pages Again!!!!! " )
            logging.info("🟡 \033[92m>>Fetching GitHub Advisories Pages Again!!!!! " )
            advisories, last_status_code = fetch_github_advisories()

    kev_ids = fetch_kevs()

    csv_data = categorize_and_zip(advisories, kev_ids)

    lines = generate_csv(csv_data, output_file_name)

     #current_datetime.strftime("%Y-%m-%d %H:%M:%S")
    end_datetime = datetime.now()
    durration = end_datetime - start_datetime
    print (f"\t\t----------------- END @ {end_datetime}----------------[Durration {durration}]--------\n")

    #lines = count_lines(output_file_name)
    print(f"🏁 \033[0mFinal Results: [Out file:\033[34m{output_file_name}\033[0m (Len:\033[35m{lines}\033[0m)]  [CISA kev_ids:\033[36m{len(kev_ids)}\033[0m]    [GitHub Advisories:\033[33m{len(advisories)}\033[0m]\n")
    logging.info(f"🏁 \033[0mFinal Results: [OutFile:\033[33m{output_file_name}\033[0m (Len:\033[35m{lines}\033[0m)]  [CISA kev_ids:\033[36m{len(kev_ids)}\033[0m]    [GitHub Advisories:\033[33m{len(advisories)}\033[0m]\n")

if __name__ == "__main__":
    main()
#==============================================================================
