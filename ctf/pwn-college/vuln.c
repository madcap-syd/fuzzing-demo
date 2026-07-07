#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Секретная функция (цель эксплуатации)
void win() {
    printf("\n🎉 ПОЗДРАВЛЯЮ! Ты нашёл флаг!\n");
    printf("🏴 Флаг: FLAG{buffer_overflow_master_2026}\n\n");
    system("/bin/sh");
}

// Уязвимая функция
void vulnerable() {
    char buffer[64];
    
    printf("╔════════════════════════════════════════╗\n");
    printf("║  🎯 CTF Challenge: Buffer Overflow     ║\n");
    printf("║  Цель: вызвать функцию win()           ║\n");
    printf("╚════════════════════════════════════════╝\n\n");
    printf("Введи данные (макс 64 байта): ");
    fflush(stdout);
    
    // УЯЗВИМОСТЬ: gets() не проверяет длину!
    gets(buffer);
    
    printf("Ты ввёл: %s\n", buffer);
}

int main() {
    // Отключаем ASLR для предсказуемости адресов
    // setenv("LD_DISABLE_RANDOMIZATION", "1", 1);
    
    vulnerable();
    
    printf("Функция win() не вызвана. Попробуй ещё раз!\n");
    return 0;
}
