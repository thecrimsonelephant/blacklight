from feeds import loadHausJSON, parseHausData, getURLID, parsing # sending in all the data from urlhaus.py and virustotal.py here to call later
import os

path = os.path.join(os.path.dirname(__file__), 'data', 'urlhaus_malicious-urls.json') # stored URLHaus data called here!

def main():
    # it's later now. Callinga ll of those imported functions
    data = loadHausJSON(path)
    all_data = parseHausData(data)
    encoded = getURLID(all_data)
    parsed = parsing(encoded)
    return parsed # returning dataframe

if __name__ == "__main__":
    df = main()
    print(df.head())  # optional: just to confirm it runs standalone (sanity check #???)
