# About code: using URLHaus data download (local) open and parse all JSON objects and return the list
# Author: Winnie Mutunga
import json

# setting up the filepath read
def loadHausJSON(path):
    with open(path, 'r') as f:
        data = json.load(f)
    # pp.pprint(data)
    return data # returning the JSON object

def parseHausData(data):
    parsed = [] # empty list init for eventual list append
    for key, entries in data.items(): # parsing JSON since it's not a nested list! 
        for item in entries: # THIS is the nested list
            parsed.append({ # appending all data
                "id": key,  # keep track of the original key
                # adding all other entries and items
                "url": item.get("url"),
                "url_status": item.get("url_status"),
                "date_added": item.get("dateadded"),
                "last_online": item.get("last_online"),
                "tags": item.get("tags", []),
                "threat": item.get("threat"),
                "reporter": item.get("reporter"),
                "urlhaus_link": item.get("urlhaus_link")
            })
    return parsed # returning list (see line 13)