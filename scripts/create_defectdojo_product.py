#!/usr/bin/env python3
"""
Создаёт Product в DefectDojo через API
"""

import requests
import json

def create_product():
    url = "http://localhost:8080/api/v2/products/"
    
    # Получаем токен (нужно сначала войти)
    login_url = "http://localhost:8080/api/v2/api-token-auth/"
    login_data = {
        "username": "admin",
        "password": "TZtV5QU3g2wCmwwDlvf6TM"
    }
    
    response = requests.post(login_url, json=login_data)
    if response.status_code != 200:
        print("❌ Не удалось получить токен")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        return None
    
    token = response.json().get('token')
    print(f"✅ Токен получен: {token[:20]}...")
    
    # Создаём продукт
    headers = {
        'Authorization': f'Token {token}',
        'Content-Type': 'application/json'
    }
    
    product_data = {
        'name': 'libxml2 Fuzzing Lab',
        'description': 'Automated fuzzing of libxml2 for CVE-2022-2309',
        'prod_type': 1,  # Research
    }
    
    response = requests.post(url, headers=headers, json=product_data)
    
    if response.status_code == 201:
        product_id = response.json()['id']
        print(f"✅ Продукт создан: ID {product_id}")
        print(f"   URL: http://localhost:8080/product/{product_id}")
        return product_id
    else:
        print(f"❌ Ошибка создания продукта")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        return None

if __name__ == "__main__":
    create_product()
