# About code: using a list of URLs, encode the URLs and strip trailing characters, hit VirusTotal API, and return specified results with proper datetime (non unixtimestamps) vals
# Author: Winnie Mutunga
from dotenv import load_dotenv # loading api key from .env file
import os
import pandas as pd
import requests
import base64
import hashlib
import datetime as dt

load_dotenv()
apikey = os.getenv("APIKEY") # storing apikey

def getURLID(all):
    df = pd.DataFrame(all) # storing parsed data in dataframe
    print(df.head()) # for my sanity (#1)
    urls = df['url'].head(3) # getting top 3 in dataframe (for testing before moving into rate limiting)
    encoded = [] # for storing encoded IDs
    print(urls) # printing urls for my sanity (#2) - ensuring they're the correct number!
    for url in urls:
        # encode URL as URL-safe base64 without trailing '=' padding as suggested in documentation
        url_bytes = url.encode('utf-8') # encoding also suggested in docs
        base64_bytes = base64.urlsafe_b64encode(url_bytes) # encoding
        base64_str = base64_bytes.decode('utf-8').rstrip("=") # stripping trailing '='
        encoded.append(base64_str) # appending encoded to list
    return encoded # returning list

def parsing(encodingURLIDs):   
    # initializing empty lists for parsing... thought about doing json_normalize and then dropping, but keys would be appended inline rather than to individual lists, so opting for this

    getURL = 'https://www.virustotal.com/api/v3/urls/' # setting up API URI to hit
    # attributes
    first_submission_date_unix = []
    last_analysis_date_unix = []
    first_submission_date = []
    last_analysis_date = []
    maliciousURL = []
    threat_names = []

    # last analysis results
    names = []
    categories = []
    engine_names = []
    methods = []
    results = []

    # setting up API headers with apikey
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }

    # print(encodingURLIDs) # triple checking urlID list. For sanity (#3)

    # looping through list of encoded URLs
    for encodingURLID in encodingURLIDs:
        # Get URL report (GET)
        try:
            response = requests.get(
                f"{getURL}/{encodingURLID}", # GET request to VT with encodedURLID
                headers=headers,
            )
            r = response.json() # storing response in json

            # print(r['data']['attributes'].keys()) # sanity check
            attributes = r['data']['attributes'] # parsing json - first up, attributes key and vals!
            last_analysis_results = r['data']['attributes']['last_analysis_results'] # getting last_analysis data

            # print(last_analysis_results)
            # not a nested list! So surfing the top with key/value and .items to get values
            for key, value in last_analysis_results.items():
                first_submission_date_unix.append(attributes['last_submission_date'])
                last_analysis_date_unix.append(attributes['last_analysis_date'])
                maliciousURL.append(attributes['url'])
                threat_names.append(attributes['threat_names'])
                # print(f"Key: {key} --- Value: {value}") # checking for fun* (*ahem, sanity. #4) 
                names.append(key)
                methods.append(value['method'])
                engine_names.append(value['engine_name'])
                categories.append(value['category'])
                results.append(value['result'])
        except Exception as e:
            print(e)
    # massive sanity check #5 but this time it's valid because if any are incorrect lengths, they won't append... maybe try/except here.
    print(len(first_submission_date_unix))
    print(len(last_analysis_date_unix))
    print(len(maliciousURL))
    print(len(threat_names))
    print(len(names))
    print(len(categories))
    print(len(engine_names))
    print(len(methods))
    print(len(results))

    # storing data in dataframe
    df = pd.DataFrame({
        'names': names,
        'first_submission_date_unix' : first_submission_date_unix,
        'last_analysis_date_unix' : last_analysis_date_unix,
        'malicious_url' : maliciousURL,
        'threat_names' : threat_names,
        'methods' : methods,
        'engine_names' : engine_names,
        'categories' : categories,
        'results': results
        })
    
    # adding sha256 uniqueID here for postgres storing
    df['composite_key'] = df['names'].astype(str) + '-' + df['malicious_url'].astype(str) # creating a column of the string version of the eventual sha256 encoded ID is faster and easier than using a function and looping through the dataframe, especially for large DFs!
    df['unique_id'] = [hashlib.sha256(x.encode()).hexdigest() for x in df['composite_key']]
    print("Created Unique IDs") # just for clarification
    
    # editing the unixtimestamps in the date fields to actual dates, and then saving to dataframe
    for unix_timestamp in df['first_submission_date_unix']:
        print(unix_timestamp)
        dates = dt.datetime.fromtimestamp(unix_timestamp)
        first_submission_date.append(dates)
    for unix_timestamp in df['last_analysis_date_unix']:
        print(unix_timestamp)
        dates = dt.datetime.fromtimestamp(unix_timestamp)
        last_analysis_date.append(dates)
    df['first_submission_date'] = first_submission_date
    df['last_analysis_date'] = last_analysis_date
    colstodrop = ['composite_key', 'first_submission_date_unix', 'last_analysis_date_unix'] # setting up columns to drop
    df = df.drop(columns=colstodrop) # dropping columns to drop (see line 97)
    df = df[sorted(df.columns)] # sorting because my brain breaks if not
    # print(df) # sanity (promise it's the last one: #6)
    return df # celebrate 🎉