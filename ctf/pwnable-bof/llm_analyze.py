#!/usr/bin/env python3
import subprocess
import json
from pathlib import Path

def analyze():
    code = Path('bof.c').read_text()
    
    prompt = f"""Analyze this C code for security vulnerabilities. Return ONLY JSON:

{code}

JSON format:
{{"vulnerabilities": [{{"type": "stack-buffer-overflow", "cwe": 121, "cvss": 9.8, "line": 8, "function": "func", "description": "gets() does not check buffer length", "fix": "Use fgets() instead of gets()", "exploit": "Overflow overflowme[32] to overwrite key parameter with 0xcafebabe"}}]}}"""

    result = subprocess.run(
        ['ollama', 'run', 'qwen2.5-coder:1.5b', prompt],
        capture_output=True, text=True, timeout=90
    )
    
    output = result.stdout.strip()
    start = output.find('{')
    end = output.rfind('}') + 1
    
    if start >= 0 and end > start:
        try:
            data = json.loads(output[start:end])
            print(json.dumps(data, indent=2))
            Path('llm_analysis.json').write_text(json.dumps(data, indent=2))
            print("\n✅ LLM analysis saved")
            return data
        except:
            pass
    
    print("Raw output:", output[:300])
    return None

if __name__ == "__main__":
    analyze()
