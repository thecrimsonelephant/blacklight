from dotenv import load_dotenv
import os
import pandas as pd
import requests
import base64
import hashlib

load_dotenv()
apikey = os.getenv("APIKEY")

def getURLID(all):
    df = pd.DataFrame(all)
    print(df.head())
    urls = df['url'].head(3)
    encoded = []
    print(urls)
    for url in urls:
        # Encode URL as URL-safe base64 without trailing '=' padding
        url_bytes = url.encode('utf-8')
        base64_bytes = base64.urlsafe_b64encode(url_bytes)
        base64_str = base64_bytes.decode('utf-8').rstrip("=")
        encoded.append(base64_str)
    return encoded
# getURLID(path)

def parsing(encodingURLIDs):   
    # attributes
    first_submission_date = []
    last_analysis_date = []
    maliciousURL = []
    threat_names = []

    # last_analysis_stats
    # harmless = []
    # malicious = []
    # undetected = []

    # last analysis results
    names = []
    categories = []
    engine_names = []
    methods = []
    results = []

    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }

    print(encodingURLIDs)

    for encodingURLID in encodingURLIDs:
        # Get URL report (GET)
        try:
            getURL = 'https://www.virustotal.com/api/v3/urls/'
            response = requests.get(
                f"{getURL}/{encodingURLID}",
                headers=headers,
            )
            r = response.json()

            # print(r['data']['attributes'].keys())
            attributes = r['data']['attributes']
            last_analysis_results = r['data']['attributes']['last_analysis_results']

            # print(last_analysis_results)
            for key, value in last_analysis_results.items():
                first_submission_date.append(attributes['last_submission_date'])
                last_analysis_date.append(attributes['last_analysis_date'])
                maliciousURL.append(attributes['url'])
                threat_names.append(attributes['threat_names'])
                # print(f"Key: {key} --- Value: {value}")
                names.append(key)
                methods.append(value['method'])
                engine_names.append(value['engine_name'])
                categories.append(value['category'])
                results.append(value['result'])
        except Exception as e:
            print(e)
    print(len(first_submission_date))
    print(len(last_analysis_date))
    print(len(maliciousURL))
    print(len(threat_names))
    print(len(names))
    print(len(categories))
    print(len(engine_names))
    print(len(methods))
    print(len(results))

    df = pd.DataFrame({
        'names': names,
        'first_submission_date' : first_submission_date,
        'last_analysis_date' : last_analysis_date,
        'malicious_url' : maliciousURL,
        'threat_names' : threat_names,
        'methods' : methods,
        'engine_names' : engine_names,
        'categories' : categories,
        'results': results

    })
    df['composite_key'] = df['names'].astype(str) + '-' + df['malicious_url'].astype(str)
    df['unique_id'] = [hashlib.sha256(x.encode()).hexdigest() for x in df['composite_key']]
    print("Created Unique IDs")
    df = df.drop(columns=['composite_key'])
    df = df[sorted(df.columns)]
    print(df)
    return df