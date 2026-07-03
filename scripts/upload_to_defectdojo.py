#!/usr/bin/env python3
import argparse
import json
import requests
import os
from pathlib import Path
from datetime import datetime

class DefectDojoAPI:
    def __init__(self, url, api_key):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': 'Token ' + api_key,
            'Content-Type': 'application/json'
        })
    
    def get_or_create_product(self, name, description=""):
        response = self.session.get(self.url + '/api/v2/products/', params={'name': name})
        if response.status_code == 200:
            results = response.json().get('results', [])
            if results:
                print("Product found: " + name + " (ID: " + str(results[0]['id']) + ")")
                return results[0]['id']
        
        data = {
            'name': name,
            'description': description or 'Product for ' + name,
            'prod_type': 1
        }
        
        response = self.session.post(self.url + '/api/v2/products/', json=data)
        if response.status_code == 201:
            product_id = response.json()['id']
            print("Product created: " + name + " (ID: " + str(product_id) + ")")
            return product_id
        
        raise Exception("Failed to create product: " + response.text)
    
    def create_engagement(self, product_id, name):
        today = datetime.now().strftime('%Y-%m-%d')
        
        data = {
            'name': name,
            'product': product_id,
            'target_start': today,
            'target_end': today,
            'engagement_type': 'CI/CD',
            'status': 'In Progress'
        }
        
        response = self.session.post(self.url + '/api/v2/engagements/', json=data)
        if response.status_code == 201:
            engagement_id = response.json()['id']
            print("Engagement created: " + name + " (ID: " + str(engagement_id) + ")")
            return engagement_id
        
        raise Exception("Failed to create engagement: " + response.text)
    
    def create_test(self, engagement_id, name):
        data = {
            'engagement': engagement_id,
            'test_type': 1,
            'title': name,
            'target_start': datetime.now().isoformat(),
            'target_end': datetime.now().isoformat()
        }
        
        response = self.session.post(self.url + '/api/v2/tests/', json=data)
        if response.status_code == 201:
            test_id = response.json()['id']
            print("Test created: " + name + " (ID: " + str(test_id) + ")")
            return test_id
        
        raise Exception("Failed to create test: " + response.text)
    
    def create_finding(self, test_id, crash):
        classification = crash['classification']
        
        description = "HonggFuzz Crash Report\n\n"
        description += "File: " + crash['filename'] + "\n"
        description += "Size: " + str(crash['size']) + " bytes\n"
        description += "Timestamp: " + crash['timestamp'] + "\n\n"
        description += "Classification:\n"
        description += "- Type: " + classification['type'] + "\n"
        description += "- CWE: CWE-" + str(classification['cwe']) + "\n"
        description += "- CVSS: " + str(classification['cvss']) + "\n"
        description += "- Severity: " + classification['severity'] + "\n"
        description += "- Signature: " + classification['signature'] + "\n\n"
        description += "Stack Trace:\n" + crash['stack_trace'][:1000] + "\n"
        
        data = {
            'title': '[HonggFuzz] ' + classification['type'] + ' in ' + crash['filename'],
            'description': description,
            'severity': classification['severity'],
            'numerical_severity': 'S0' if classification['severity'] == 'Critical' else 'S1' if classification['severity'] == 'High' else 'S2' if classification['severity'] == 'Medium' else 'S3',
            'cwe': classification['cwe'],
            'cvssv3_score': classification['cvss'],
            'test': test_id,
            'found_by': [1],
            'active': True,
            'verified': False,
            'false_p': False,
            'duplicate': False,
            'unique_id_from_tool': classification['signature'],
            'mitigation': 'Review and fix the root cause',
            'impact': classification['type'] + ' vulnerability detected by HonggFuzz',
            'references': 'https://cwe.mitre.org/data/definitions/' + str(classification['cwe']) + '.html'
        }
        
        response = self.session.post(self.url + '/api/v2/findings/', json=data)
        if response.status_code == 201:
            finding_id = response.json()['id']
            print("  Finding created: " + classification['type'] + " (ID: " + str(finding_id) + ")")
            return finding_id
        elif response.status_code == 400 and 'unique_id_from_tool' in response.text:
            print("  Finding already exists: " + classification['type'])
            return None
        
        raise Exception("Failed to create finding: " + response.text)

def main():
    parser = argparse.ArgumentParser(description='Upload fuzzing results to DefectDojo')
    parser.add_argument('--results', type=Path, required=True, help='JSON file with crash results')
    parser.add_argument('--product', type=str, required=True, help='Product name')
    parser.add_argument('--engagement', type=str, required=True, help='Engagement name')
    
    args = parser.parse_args()
    
    dd_url = os.getenv('DEFECTDOJO_URL', 'http://localhost:8080')
    dd_api_key = os.getenv('DEFECTDOJO_API_KEY', 'TZtV5QU3g2wCmwwDlvf6TM')
    
    print("Connecting to DefectDojo: " + dd_url)
    
    results = json.loads(args.results.read_text())
    crashes = results.get('crashes', [])
    summary = results.get('summary', {})
    
    print("Found crashes: " + str(summary.get('total_crashes', 0)))
    print("Unique bugs: " + str(summary.get('unique_bugs', 0)))
    
    if not crashes:
        print("No crashes found")
        return
    
    api = DefectDojoAPI(dd_url, dd_api_key)
    
    product_id = api.get_or_create_product(args.product, "HonggFuzz security testing")
    engagement_id = api.create_engagement(product_id, args.engagement)
    test_id = api.create_test(engagement_id, "HonggFuzz Automated Testing")
    
    print("\nCreating findings...")
    findings_created = 0
    
    for crash in crashes:
        try:
            finding_id = api.create_finding(test_id, crash)
            if finding_id:
                findings_created += 1
        except Exception as e:
            print("  Error creating finding: " + str(e))
    
    print("\nCreated findings: " + str(findings_created) + "/" + str(len(crashes)))
    print("Open DefectDojo: " + dd_url)

if __name__ == '__main__':
    main()
