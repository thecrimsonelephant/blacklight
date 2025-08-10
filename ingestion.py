from feeds import loadHausJSON, parseHausData, getURLID, parsing
import pandas as pd
import os
path = os.path.join(os.path.dirname(__file__), 'data', 'urlhaus_malicious-urls.json')

def main():
    data = loadHausJSON(path)
    all = parseHausData(data)
    encoded = getURLID(all)
    parsed = parsing(encoded)
    print(parsed)

if __name__ == "__main__":
    main()