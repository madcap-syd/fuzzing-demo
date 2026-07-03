#!/bin/bash
# Синхронизация fuzzing corpus с MinIO
# Использование: ./sync_corpus_minio.sh [project_name] [corpus_dir]

set -e

MINIO_ALIAS="local"
PROJECT_NAME="${1:-fuzzing-demo}"
CORPUS_DIR="${2:-corpus}"
BUCKET_PATH="fuzzing-corpus/${PROJECT_NAME}"

echo "🔄 Синхронизация corpus с MinIO..."
echo "   Проект: $PROJECT_NAME"
echo "   Локальная папка: $CORPUS_DIR"
echo "   MinIO путь: $BUCKET_PATH"

# Скачиваем существующий corpus из MinIO
echo "📥 Скачиваем corpus из MinIO..."
mc mirror --overwrite "${MINIO_ALIAS}/${BUCKET_PATH}" "$CORPUS_DIR" 2>/dev/null || \
    echo "ℹ️  Corpus пустой в MinIO, начинаем с нуля"

# Фаззер работает... (здесь вызывается libFuzzer/Jazzer.js)
# После работы фаззера — загружаем обновлённый corpus обратно
echo "📤 Загружаем обновлённый corpus в MinIO..."
mc mirror --overwrite "$CORPUS_DIR" "${MINIO_ALIAS}/${BUCKET_PATH}"

echo "✅ Синхронизация завершена"
echo "📊 Статистика:"
mc du "${MINIO_ALIAS}/${BUCKET_PATH}"
