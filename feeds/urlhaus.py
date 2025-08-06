# Parsing URLhause JSON dump of malicious and active malware URLs

import json
import pandas as pd
import pprint as pp

def load_urlhaus_json(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data

def parse_urlhaus_data(data):
    payloads = data.get("urls", [])
    parsed = []
    for item in payloads:
        parsed.append({
            "url": item.get("url"),
            "host": item.get("host"),
            "date_added": item.get("date_added"),
            "tags": item.get("tags", []),
            "url_status": item.get("url_status"),
            "threat": item.get("threat"),
            "reporter": item.get("reporter")
        })
    return parsed
from feeds.urlhaus import load_urlhaus_json, parse_urlhaus_data

data = load_urlhaus_json("data/urlhaus.json")
parsed_urls = parse_urlhaus_data(data)

print(f"Parsed {len(parsed_urls)} URLs.")
