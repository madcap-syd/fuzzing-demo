#!/usr/bin/env python3
import json
import requests
import argparse
from pathlib import Path

class DefectDojoAPI:
    def __init__(self, url, api_key):
        self.url = url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {api_key}',
            'Content-Type': 'application/json'
        })
    
    def get_findings_by_title(self, title):
        response = self.session.get(f"{self.url}/api/v2/findings/", params={'title': title})
        if response.status_code == 200:
            results = response.json().get('results', [])
            return results[0]['id'] if results else None
        return None
    
    def update_finding(self, finding_id, llm_analysis, crash_data):
        description = f"""## LLM Analysis

**Type:** {llm_analysis.get('type', 'unknown')}
**CWE:** CWE-{llm_analysis.get('cwe', 0)}
**CVSS:** {llm_analysis.get('cvss', 0.0)}
**Severity:** {llm_analysis.get('severity', 'Medium')}

### Description
{llm_analysis.get('description', 'No description')}

### Fix Recommendation
{llm_analysis.get('fix_recommendation', 'No recommendation')}

### Impact
{llm_analysis.get('impact', 'Unknown')}

### Crash File: {crash_data.get('filename', 'unknown')}
"""
        data = {
            'description': description,
            'mitigation': llm_analysis.get('fix_recommendation', 'Review and fix'),
            'impact': llm_analysis.get('impact', 'Unknown'),
            'references': f"https://cwe.mitre.org/data/definitions/{llm_analysis.get('cwe', 0)}.html"
        }
        response = self.session.patch(f"{self.url}/api/v2/findings/{finding_id}/", json=data)
        return response.status_code in [200, 204]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--llm-results', type=Path, required=True)
    parser.add_argument('--api-key', type=str, required=True)
    parser.add_argument('--url', type=str, default='http://localhost:8080')
    args = parser.parse_args()
    
    with open(args.llm_results) as f:
        data = json.load(f)
    
    api = DefectDojoAPI(args.url, args.api_key)
    crashes = data.get('crashes', [])
    print(f"Updating {len(crashes)} findings in DefectDojo...")
    
    updated = 0
    for i, crash in enumerate(crashes):
        llm_analysis = crash.get('llm_analysis')
        if not llm_analysis:
            continue
        title = f"[HonggFuzz] {llm_analysis.get('type', 'unknown')} in {crash.get('filename', 'unknown')}"
        finding_id = api.get_findings_by_title(title)
        if finding_id:
            if api.update_finding(finding_id, llm_analysis, crash):
                print(f"  ✅ [{i+1}] {crash['filename']}")
                updated += 1
            else:
                print(f"  ❌ [{i+1}] {crash['filename']} - update failed")
        else:
            print(f"  ⚠️  [{i+1}] {crash['filename']} - not found")
    
    print(f"\n✅ Updated: {updated}/{len(crashes)}")

if __name__ == '__main__':
    main()
