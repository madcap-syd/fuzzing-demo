#!/usr/bin/env python3
"""
Создаёт Engagement в DefectDojo
"""

import requests
from datetime import datetime

def create_engagement(product_id: int):
    url = "http://localhost:8080/api/v2/engagements/"
    
    # Логин
    login_url = "http://localhost:8080/api/v2/api-token-auth/"
    login_data = {
        "username": "admin",
        "password": "TZtV5QU3g2wCmwwDlvf6TM"
    }
    
    response = requests.post(login_url, json=login_data)
    token = response.json().get('token')
    
    headers = {
        'Authorization': f'Token {token}',
        'Content-Type': 'application/json'
    }
    
    # Создаём engagement
    today = datetime.now().strftime('%Y-%m-%d')
    
    engagement_data = {
        'name': f'Fuzzing {today}',
        'product': product_id,
        'target_start': today,
        'target_end': today,
        'engagement_type': 'CI/CD',
        'status': 'In Progress',
        'description': 'Automated fuzzing with libFuzzer + LLM analysis',
    }
    
    response = requests.post(url, headers=headers, json=engagement_data)
    
    if response.status_code == 201:
        engagement_id = response.json()['id']
        print(f"✅ Engagement создан: ID {engagement_id}")
        print(f"   URL: http://localhost:8080/engagement/{engagement_id}")
        return engagement_id
    else:
        print(f"❌ Ошибка: {response.status_code}")
        print(f"   {response.text}")
        return None

if __name__ == "__main__":
    # Сначала получаем product_id (предполагаем, что это первый продукт)
    create_engagement(product_id=1)
