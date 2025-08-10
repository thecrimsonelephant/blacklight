from feeds import loadHausJSON, parseHausData, getURLID, parsing
import os

path = os.path.join(os.path.dirname(__file__), 'data', 'urlhaus_malicious-urls.json')

def main():
    data = loadHausJSON(path)
    all_data = parseHausData(data)
    encoded = getURLID(all_data)
    parsed = parsing(encoded)
    return parsed

if __name__ == "__main__":
    df = main()
    print(df.head())  # optional: just to confirm it runs standalone
