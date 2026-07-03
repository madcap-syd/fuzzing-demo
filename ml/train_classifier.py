#!/usr/bin/env python3
"""
Обучение ML-классификатора для FP-фильтрации

Алгоритм: Gradient Boosting (scikit-learn)
Признаки: 13 features (stack trace, crash type, file info)
Цель: предсказать FP с точностью > 90%
"""

import json
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

def load_data():
    """Загружает обучающие данные"""
    with open('ml/training_data.json') as f:
        data = json.load(f)
    
    # Разделяем features и labels
    X = []
    y = []
    for sample in data:
        features = [
            sample['stack_trace_length'],
            sample['has_our_code'],
            sample['has_test_keyword'],
            sample['has_debug_keyword'],
            sample['has_memory_keyword'],
            sample['crash_type_heap'],
            sample['crash_type_uaf'],
            sample['crash_type_stack'],
            sample['crash_type_null'],
            sample['file_extension_cpp'],
            sample['file_extension_js'],
            sample['function_depth'],
        ]
        X.append(features)
        y.append(sample['label'])
    
    return np.array(X), np.array(y)

def train_model():
    """Обучает модель"""
    print("📊 Загрузка данных...")
    X, y = load_data()
    print(f"   Примеров: {len(X)}")
    print(f"   Признаков: {X.shape[1]}")
    
    # Разделяем на train/test (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n🎯 Обучение модели...")
    print(f"   Train: {len(X_train)} примеров")
    print(f"   Test:  {len(X_test)} примеров")
    
    # Gradient Boosting Classifier
    model = GradientBoostingClassifier(
        n_estimators=100,      # 100 деревьев
        learning_rate=0.1,     # скорость обучения
        max_depth=5,           # глубина деревьев
        random_state=42
    )
    
    model.fit(X_train, y_train)
    
    # Предсказания на тестовой выборке
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    # Метрики
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n📈 РЕЗУЛЬТАТЫ:")
    print(f"   Accuracy: {accuracy:.2%}")
    print(f"\n📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['TP (Real Bug)', 'FP (False Positive)']))
    
    print(f"🔢 Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"   TN (правильно TP): {cm[0][0]}")
    print(f"   FP (ошибка):       {cm[0][1]}")
    print(f"   FN (ошибка):       {cm[1][0]}")
    print(f"   TP (правильно FP): {cm[1][1]}")
    
    # Feature importance
    feature_names = [
        'stack_trace_length', 'has_our_code', 'has_test_keyword',
        'has_debug_keyword', 'has_memory_keyword', 'crash_type_heap',
        'crash_type_uaf', 'crash_type_stack', 'crash_type_null',
        'file_extension_cpp', 'file_extension_js', 'function_depth'
    ]
    
    print(f"\n🔍 Feature Importance (топ-5):")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:5]
    for i in indices:
        print(f"   {feature_names[i]:25} {importances[i]:.3f}")
    
    # Сохраняем модель
    model_path = Path('ml/fp_classifier.pkl')
    joblib.dump(model, model_path)
    print(f"\n✅ Модель сохранена: {model_path}")
    
    return model

if __name__ == "__main__":
    train_model()
