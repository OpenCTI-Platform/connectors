import sys
# Importing the JSON module
import json
# Importing the different stix2 modules
from stix2 import MemoryStore
from stix2 import Vulnerability
from stix2 import Bundle

def convert(filename, output='output.json'):
    count = 0
    with open(filename) as json_file:
        vList = []
        data = json.load(json_file)

        print("Loaded the file")
        for cves in data['CVE_Items']:
                count += 1
                # Getting the different fields
                name = cves['cve']['CVE_data_meta']['ID']
                description = cves['cve']['description']['description_data'][0]["value"]
                cdate = cves['publishedDate']
                mdate = cves['lastModifiedDate']
                creator = cves['cve']['CVE_data_meta']['ASSIGNER']

                # Creating the vulnerability with the extracted fields
                vuln = Vulnerability(name=name, created=cdate, modified=mdate, description=description)

                # Adding the vulnerability to the list of vulnerabilities    
                vList.append(vuln)
    # Creating the bundle from the list of vulnerabilities
    bundle = Bundle(vList)
    # Creating a MemoryStore object from the bundle
    memorystore = MemoryStore(bundle)
    # Dumping this object to a file
    memorystore.save_to_file(output)

    print("Successfully converted " + str(count) + " vulnerabilities")

if __name__ == '__main__':
    convert(sys.argv[1], sys.argv[2])