
#!/usr/bin/env python3
import os
import sys
import json
import requests

def fetch_package_versions(package_name):
    url = f"https://registry.npmjs.org/{package_name}"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Error: Unable to fetch package data (status code {response.status_code}).")
        sys.exit(1)
    data = response.json()
    # The 'versions' field is a dict with version numbers as keys.
    return list(data.get("versions", {}).keys())

def create_output_file(package_name, versions):
    # Define the folder and file names.
    folder_name = package_name
    filename = f"MAL-0000-{package_name}.json"
    file_path = os.path.join(folder_name, filename)
    
    # Template JSON content with versions inserted.
    output = {
        "modified": "2025-02-03T17:25:15Z",
        "published": "2025-02-03T17:25:15Z",
        "schema_version": "1.5.0",
        "summary": f"Malicious code in {package_name} (npm)",
        "details": "The package communicates with a domain associated with malicious activity.",
        "affected": [{
            "package": {
                "ecosystem": "npm",
                "name": package_name
            },
            "versions": versions
        }],
        "credits": [{
            "name": "Amazon Inspector",
            "type": "FINDER",
            "contact": [
                "actran@amazon.com"
            ]
        }]
    }
    
    # Write the JSON data to the file.
    with open(file_path, "w") as outfile:
        json.dump(output, outfile, indent=4)
    
    print(f"File created: {file_path}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <npm_package_name>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    
    # Check if the folder already exists.
    if os.path.exists(package_name):
        print(f"Folder '{package_name}' already exists. Aborting.")
        sys.exit(1)
    
    print(f"Fetching versions for package: {package_name}")
    versions = fetch_package_versions(package_name)
    
    if not versions:
        print("No versions found for the package.")
        sys.exit(1)
    
    print(f"Found {len(versions)} versions.")
    
    # Create the folder now since it does not exist.
    os.makedirs(package_name, exist_ok=True)
    
    create_output_file(package_name, versions)

if __name__ == "__main__":
    main()