import sys
import requests
import getopt
import json
import urllib.parse
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import time
import xml.etree.ElementTree as ET  # for parsing XML

from veracode_api_signing.credentials import get_credentials

class NoExactMatchFoundException(Exception):
    message=""
    def __init__(self, message_to_set):
        self.message = message_to_set

    def get_message(self):
        return self.message
    
class SCA_Finding:
    description: str
    severity: str
    cwe_id: int
    cwe_name: str
    cve: str
    cvss2: str
    cve_link: str
    cvss3: str
    epss_score: str
    epss_percentile: str
    component_name: str
    component_version: str

    def __init__(self, description: str, severity: str, cwe_id:int, cwe_name:str, cve: str, cvss2: str, cve_link: str, cvss3: str, epss_score: str, epss_percentile: str, component_name: str, component_version: str):
        self.description = description
        self.severity = severity
        self.cwe_id = cwe_id
        self.cwe_name = cwe_name
        self.cve = cve
        self.cvss2 = cvss2
        self.cve_link = cve_link
        self.cvss3 = cvss3
        self.epss_score = epss_score
        self.epss_percentile = epss_percentile
        self.component_name = component_name
        self.component_version = component_version

class SAST_Finding:
    issue_id: str
    description: str
    severity: str
    cwe_id: int
    cwe_name: str
    file_path: str
    line_number: int
    finding_category: str
    

    def __init__(self, issue_id: str, description: str, severity: str, cwe_id: int, cwe_name: str, file_path: str, line_number: int, finding_category: str):
        self.issue_id = issue_id
        self.description = description
        self.severity = severity
        self.cwe_id = cwe_id
        self.cwe_name = cwe_name
        self.file_path = file_path
        self.line_number = line_number
        self.finding_category = finding_category

class Results_filters:
    minimum_severity : int
    consider_sca : bool

    def __init__(self, minimum_severity, consider_sca):
        self.minimum_severity = minimum_severity
        self.consider_sca = consider_sca

    def get_api_filters(self):
        return f"severity_gte={self.minimum_severity}"

json_headers = {
    "User-Agent": "Bulk application creation - python script",
    "Content-Type": "application/json"
}

failed_attempts = 0
max_attempts_per_request = 10
sleep_time = 10


def print_help():
    """Prints command line options and exits"""
    print("""veracode-verify-scan-results.py -a <application_name> -m <minimum_severity> [--sandbox_name <sandbox_name>] [-s] [-f (fail if results are found)] [-d]"
        Reads the results of the latest scan for the application called <application_name>, (and optionally a sandbox called <sandbox_name>).
        Returns all the results that are of severity <minimum_severity> or greater (optionally including SCA results if -s is passed)
        Passing the -f flag will return an error code equal to the number of findings identified.
""")
    sys.exit()

def print_half_line_across():
    print("---------------------------------------------")

def print_line_across():
    print("------------------------------------------------------------------------------------------")

def request_encode(value_to_encode):
    return urllib.parse.quote(value_to_encode, safe='')

def get_error_node_value(body):
    inner_node = ET.XML(body)
    if inner_node.tag == "error" and not inner_node == None:
        return inner_node.text
    else:
        return ""

def find_exact_match(list, to_find, field_name, list_name2):
    if list_name2:
        for index in range(len(list)):
            if (list_name2 and list[index][list_name2][field_name].lower() == to_find.lower()):
                return list[index]
    
        print(f"Unable to find a member of list with {field_name}+{list_name2} equal to {to_find}")
        raise NoExactMatchFoundException(f"Unable to find a member of list with {field_name}+{list_name2} equal to {to_find}")
    else:
        for index in range(len(list)):
            if list[index][field_name].lower() == to_find.lower():
                return list[index]

        print(f"Unable to find a member of list with {field_name} equal to {to_find}")
        raise NoExactMatchFoundException(f"Unable to find a member of list with {field_name} equal to {to_find}")

def get_item_from_api_call(api_base, api_to_call, item_to_find, list_name, list_name2, field_to_check, field_to_get, is_exact_match, verbose):
    global failed_attempts
    global sleep_time
    global max_attempts_per_request
    path = f"{api_base}{api_to_call}"
    if verbose:
        print(f"Calling: {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)
    data = response.json()

    if response.status_code == 200:
        if verbose:
            print(data)
        if "_embedded" in data and len(data["_embedded"][list_name]) > 0:
            if list_name2:
                return (find_exact_match(data["_embedded"][list_name], item_to_find, field_to_check, list_name2) if is_exact_match else data["_embedded"][list_name][list_name2][0])[field_to_get]
            else:
                return (find_exact_match(data["_embedded"][list_name], item_to_find, field_to_check, list_name2) if is_exact_match else data["_embedded"][list_name][0])[field_to_get]
        else:
            print(f"ERROR: No {list_name}+{list_name2} named '{item_to_find}' found")
            return f"ERROR: No {list_name}+{list_name2} named '{item_to_find}' found"
    else:
        print(f"ERROR: trying to get {list_name}+{list_name2} named {item_to_find}")
        print(f"ERROR: code: {response.status_code}")
        print(f"ERROR: value: {data}")
        failed_attempts+=1
        if (failed_attempts < max_attempts_per_request):
            time.sleep(sleep_time)
            return get_item_from_api_call(api_base, api_to_call, item_to_find, list_name, list_name2, field_to_check, field_to_get, verbose)
        else:
            return f"ERROR: trying to get {list_name}+{list_name2} named {item_to_find}"

def get_max_page(body):
    return body["page"]["total_pages"]

def severity_to_str(severity):
    match severity:
        case 5:
            return "Very High"
        case 4:
            return "High"
        case 3:
            return "Medium"
        case 2:
            return "Low"
        case 1:
            return "Very Low"
        case 0:
            return "Informational"
    return f"Invalid severity: {severity}"

def is_open_finding(finding) -> bool:
    return "finding_status" in finding and finding["finding_status"]["status"] == "OPEN"

def parse_sast_results_page(body):
    if not "_embedded" in body or not "findings" in body["_embedded"]:
        return []
    finding_list = []
    for finding in body["_embedded"]["findings"]:
        if is_open_finding(finding):
            finding_list.append(SAST_Finding(finding["issue_id"], finding["description"], severity_to_str(finding["finding_details"]["severity"]), 
                                             finding["finding_details"]["cwe"]["id"], finding["finding_details"]["cwe"]["name"], 
                                             finding["finding_details"]["file_path"], finding["finding_details"]["file_line_number"], 
                                             finding["finding_details"]["finding_category"]["name"]))
    return finding_list

def get_sast_findings_page(base_path, page, verbose, max_page):
    path = f"{base_path}{page}"

    if verbose:
        print(f"Calling API at: {path}")
    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)

    body = response.json()    

    if verbose:
        print(f"status code {response.status_code}")
        if body:
            print(body)
    if response.status_code == 200:
        return parse_sast_results_page(body), get_max_page(body)
    else:
        body = response.json()
        if (body):
            print(f"Unable to get page: {response.status_code} - {body}")
        else:
            print(f"Unable to get page: {response.status_code}")
    return None, max_page

def handle_retry(page, max_page,  finding_type, application_guid, sandbox_filter):
    global failed_attempts
    global sleep_time
    global max_attempts_per_request

    failed_attempts+=1
    if (failed_attempts < max_attempts_per_request):
        time.sleep(sleep_time)
    else:
        print(f"Unable to get {finding_type} findings page {page}/{max_page} for application {application_guid}{(f" + {sandbox_filter}") if sandbox_filter else ""}")
        sys.exit(-1)

def get_sast_findings(api_base, application_guid, results_filter_string, sandbox_filter, verbose): 
    page = 0
    max_page=1    
    sast_findings = []
    base_path = f"{api_base}appsec/v2/applications/{application_guid}/findings?scan_type=STATIC&{results_filter_string}{sandbox_filter}&page="

    while page < max_page:
        findings_page, max_page = get_sast_findings_page(base_path, page, verbose, max_page) 
        if not findings_page:
            handle_retry(page, max_page, "SAST", application_guid, sandbox_filter) 
        else:
            sast_findings.extend(findings_page)
            page = page+1
        
    return sast_findings

def get_exploitability_node(cve_node):
    if not "exploitability" in cve_node:
        return False
    return cve_node["exploitability"] if cve_node["exploitability"]["epss_status"] == "match found" else None

def parse_sca_results_page(body):
    if not "_embedded" in body or not "findings" in body["_embedded"]:
        return []
    finding_list = []
    for finding in body["_embedded"]["findings"]:
        if is_open_finding(finding):
            finding_details = finding["finding_details"]
            cwe_id = "" if not "cwe" in finding_details else finding_details["cwe"]["id"]
            cwe_name = "" if not "cwe" in finding_details else finding_details["cwe"]["name"]

            exploitability_node = get_exploitability_node(finding_details["cve"])
            epss_score = "" if not exploitability_node else exploitability_node["epss_score"]
            epss_percentile = "" if not exploitability_node else exploitability_node["epss_percentile"]
            finding_list.append(SCA_Finding(finding["description"], severity_to_str(finding["finding_details"]["severity"]),
                                            cwe_id, cwe_name, finding_details["cve"]["name"], finding_details["cve"]["cvss"], 
                                            finding_details["cve"]["href"], finding_details["cve"]["cvss3"]["score"], 
                                            epss_score, epss_percentile, finding["finding_details"]["component_filename"], finding["finding_details"]["version"]))
    return finding_list
    
def get_sca_findings_page(base_path, page, verbose, max_page):
    path = f"{base_path}{page}"
    if verbose:
        print(f"Calling API at: {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)

    body = response.json()
    if verbose:
        print(f"status code {response.status_code}")        
        if body:
            print(body)
    if response.status_code == 200:
        return parse_sca_results_page(body), get_max_page(body)
    else:
        body = response.json()
        if (body):
            print(f"Unable to get page: {response.status_code} - {body}")
        else:
            print(f"Unable to get page: {response.status_code}")
    return None, max_page

def get_sca_findings(api_base, application_guid, results_filter_string, sandbox_filter, verbose):
    page = 0
    max_page=1    
    sca_findings = []
    base_path = f"{api_base}appsec/v2/applications/{application_guid}/findings?scan_type=SCA&{results_filter_string}{sandbox_filter}&page="

    while page < max_page:
        findings_page, max_page = get_sca_findings_page(base_path, page, verbose, max_page) 
        if not findings_page:
            handle_retry(page, max_page, "SAST" ,application_guid) 
        else:
            sca_findings.extend(findings_page)
            page = page+1
        
    return sca_findings

def print_sast(sast_findings):
    for finding in sast_findings:
        print(f"  Issue ID: {finding.issue_id}")
        print(f"  Description: {finding.description}")
        print(f"  Severity: {finding.severity}")
        print(f"  CWE: {finding.cwe_id}")
        print(f"  CWE Name: {finding.cwe_name}")
        print(f"  File Path: {finding.file_path}")
        print(f"  Line Number: {finding.line_number}")
        print(f"  Finding Category: {finding.finding_category}")
        print_half_line_across()

def print_sca(sca_findings):
    for finding in sca_findings:
        print(f"  Component Name: {finding.component_name}")
        print(f"  Component Version: {finding.component_version}")
        print(f"  Description: {finding.description}")
        print(f"  Severity: {finding.severity}")
        print(f"  CWE: {finding.cwe_id}")
        print(f"  CWE Name: {finding.cwe_name}")
        print(f"  CVE: {finding.cve}")
        print(f"  CVE Link: {finding.cve_link}")
        print(f"  CVSSv2: {finding.cvss2}")
        print(f"  CVSSv3: {finding.cvss3}")
        print(f"  EPSS Score: {finding.epss_score}")
        print(f"  EPSS Percentile: {finding.epss_percentile}")
        print_half_line_across()
        

def read_scan_results(api_base, application_name, sandbox_name, results_filters: Results_filters, fail_on_findings, verbose):
    print(f"Getting scan results for application: {application_name}")
    if sandbox_name:
        print(f"    and sandbox: {sandbox_name}")

    application_guid = get_item_from_api_call(api_base, "appsec/v1/applications?name="+ request_encode(application_name.strip()), application_name.strip(), "applications", "profile", "name", "guid", True, verbose)
    sandbox_guid = ""
    if sandbox_name:
        sandbox_guid = get_item_from_api_call(api_base, f"appsec/v1/applications/{application_guid}/sandboxes?size=500", sandbox_name.strip(), "sandboxes", None, "name", "guid", True, verbose)
    
    results_filter_string = results_filters.get_api_filters()
    sandbox_filter = f"context={sandbox_guid}" if sandbox_guid else ""

    sast_findings = get_sast_findings(api_base, application_guid, results_filter_string, sandbox_filter, verbose)
    if results_filters.consider_sca:
        sca_findings = get_sca_findings(api_base, application_guid, results_filter_string, sandbox_filter, verbose)
    
    print_line_across()
    total_findings = 0
    if sast_findings:
        total_findings = len(sast_findings)
        print(f"Found {total_findings} SAST findings:")
        print_sast(sast_findings)
    else:
        print("Found no SAST findings.")
    print_line_across()

    if results_filters.consider_sca:
        print("")
        if sca_findings:
            total_findings = total_findings + len(sca_findings)
            print(f"Found {len(sca_findings)} SCA findings:")
            print_sca(sca_findings)
        else:
            print("Found no SCA findings.")
        print_line_across()
    if fail_on_findings:
        sys.exit(total_findings)

def get_api_base():

    api_key_id, _ = get_credentials()
    api_base = "https://api.veracode.{instance}/"
    if api_key_id.startswith("vera01"):
        return api_base.replace("{instance}", "eu", 1)
    else:
        return api_base.replace("{instance}", "com", 1)

def main(argv):
    """Allows for reporting on Veracode scan results"""
    try:
        verbose = False
        application_name = ''
        minimum_severity = -1
        sandbox_name = ''
        fail_on_findings = False
        consider_sca = False

        opts, args = getopt.getopt(argv, "hdfsa:m:", ["application_name=", "minimum_severity=", "sandbox_name="])
        for opt, arg in opts:
            if opt == '-h':
                print_help()
            if opt == '-d':
                verbose = True
            if opt == '-f':
                fail_on_findings = True
            if opt == '-s':
                consider_sca = True
            if opt in ('-a', '--application_name'):
                application_name=arg
            if opt in ('-m', '--minimum_severity'):
                minimum_severity=int(arg)
            if opt == '--sandbox_name':
                sandbox_name=arg

        api_base = get_api_base()
        if application_name and minimum_severity > 0:
            read_scan_results(api_base, application_name, sandbox_name, Results_filters(minimum_severity, consider_sca), fail_on_findings, verbose)
        else:
            print_help()
    except requests.RequestException as e:
        print("An error occurred!")
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
