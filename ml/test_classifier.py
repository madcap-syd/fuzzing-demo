#!/usr/bin/env python3
"""
Тестирование ML-классификатора на новых примерах
"""

import joblib
import numpy as np
from pathlib import Path

def predict_crash(model, crash_features):
    """
    Предсказывает FP/TP для одного краша
    
    crash_features: dict с 12 признаками
    """
    features = np.array([[
        crash_features['stack_trace_length'],
        crash_features['has_our_code'],
        crash_features['has_test_keyword'],
        crash_features['has_debug_keyword'],
        crash_features['has_memory_keyword'],
        crash_features['crash_type_heap'],
        crash_features['crash_type_uaf'],
        crash_features['crash_type_stack'],
        crash_features['crash_type_null'],
        crash_features['file_extension_cpp'],
        crash_features['file_extension_js'],
        crash_features['function_depth'],
    ]])
    
    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0]
    
    return {
        'is_fp': bool(prediction),
        'confidence': float(probability[prediction]),
        'label': 'FP' if prediction else 'TP'
    }

def main():
    # Загружаем модель
    model = joblib.load('ml/fp_classifier.pkl')
    print("✅ Модель загружена\n")
    
    # Тестовые примеры
    test_cases = [
        {
            'name': 'Реальный heap-buffer-overflow',
            'features': {
                'stack_trace_length': 10,
                'has_our_code': 0.8,
                'has_test_keyword': 0.05,
                'has_debug_keyword': 0.05,
                'has_memory_keyword': 0.6,
                'crash_type_heap': 1,
                'crash_type_uaf': 0,
                'crash_type_stack': 0,
                'crash_type_null': 0,
                'file_extension_cpp': 1,
                'file_extension_js': 0,
                'function_depth': 7,
            }
        },
        {
            'name': 'OOM (Out of Memory)',
            'features': {
                'stack_trace_length': 3,
                'has_our_code': 0.1,
                'has_test_keyword': 0.0,
                'has_debug_keyword': 0.0,
                'has_memory_keyword': 0.95,
                'crash_type_heap': 0,
                'crash_type_uaf': 0,
                'crash_type_stack': 0,
                'crash_type_null': 0,
                'file_extension_cpp': 1,
                'file_extension_js': 0,
                'function_depth': 2,
            }
        },
        {
            'name': 'Debug assert в тесте',
            'features': {
                'stack_trace_length': 5,
                'has_our_code': 0.3,
                'has_test_keyword': 0.5,
                'has_debug_keyword': 0.9,
                'has_memory_keyword': 0.2,
                'crash_type_heap': 0,
                'crash_type_uaf': 0,
                'crash_type_stack': 0,
                'crash_type_null': 0,
                'file_extension_cpp': 1,
                'file_extension_js': 0,
                'function_depth': 4,
            }
        },
        {
            'name': 'Use-after-free в production',
            'features': {
                'stack_trace_length': 12,
                'has_our_code': 0.9,
                'has_test_keyword': 0.0,
                'has_debug_keyword': 0.0,
                'has_memory_keyword': 0.7,
                'crash_type_heap': 0,
                'crash_type_uaf': 1,
                'crash_type_stack': 0,
                'crash_type_null': 0,
                'file_extension_cpp': 1,
                'file_extension_js': 0,
                'function_depth': 9,
            }
        },
    ]
    
    print("🧪 ТЕСТОВЫЕ ПРЕДСКАЗАНИЯ:")
    print("="*70)
    
    for case in test_cases:
        result = predict_crash(model, case['features'])
        print(f"\n📋 {case['name']}:")
        print(f"   Prediction: {result['label']}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Is FP:      {result['is_fp']}")

if __name__ == "__main__":
    main()
