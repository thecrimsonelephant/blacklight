import json

def loadHausJSON(path):
    with open(path, 'r') as f:
        data = json.load(f)
    # pp.pprint(data)
    return data

def parseHausData(data):
    parsed = []
    for key, entries in data.items():
        for item in entries:
            parsed.append({
                "id": key,  # keep track of the original key
                "url": item.get("url"),
                "url_status": item.get("url_status"),
                "date_added": item.get("dateadded"),
                "last_online": item.get("last_online"),
                "tags": item.get("tags", []),
                "threat": item.get("threat"),
                "reporter": item.get("reporter"),
                "urlhaus_link": item.get("urlhaus_link")
            })
    return parsed