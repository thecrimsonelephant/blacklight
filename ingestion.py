from feeds import loadHausJSON, parseHausData
import pandas as pd

def main():
    data = loadHausJSON('data/urlhaus_malicious-urls.json')
    parsedURLs = parseHausData(data)
    print(f'Parsing {len(parsedURLs)} URLs')
    # Check the first 3 entries
    df = pd.DataFrame(parsedURLs)
    print(df)

if __name__ == "__main__":
    main()