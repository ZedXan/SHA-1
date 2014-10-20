#include <string>                                                                       //Для string
#include <iostream>                                                                     //Для cout 
#include <sstream>                                                                      //Для ostringstream и функции hex
#include <fstream>                                                                      //Для файлов

using namespace std;                                                                    //Для cout, hex и файлов

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))                            //Битовый сдвиг на n бит
 
class SHA_1                                                                             //Класс
{
    string message;                                                                     //Исходное сообщение

    unsigned long long bitlen;                                                          //Исходная длина сообщения (до шага 1) в битах

    unsigned char M[64];                                                                //Сообщение блоками по 64 байта

    unsigned int W[80];                                                                 //Массив 32-битных слов

    unsigned int K[4];                                                                  //Вспомогательные константы

    unsigned int H0, H1, H2, H3, H4;                                                    //Регистры SHA буфера

    unsigned int A, B, C, D, E, T;                                                      //Переменные для сохранения значений регистров во время алгоритма                                                                   
    
    unsigned int F(unsigned int j, unsigned int x, unsigned int y, unsigned int z);     //Выбор битовой функции в соответсвии с номером цикла
   
    void extension();                                                                   //Шаг 1 - Расширение сообщения
    void adding_length();                                                               //Шаг 2 - Добавление длины сообщения
    void initialize_sha();                                                              //Шаг 3 - Инициализация SHA буфера
    void message_processing();                                                          //Шаг 4 - Обработка сообщения в блоках
    ostringstream result;                                                               //Шаг 5 - Результат в виде хэш-сообщения
public:
    bool read_file(char *fileName);                                                     //Чтение из файла
    bool write_file(char *fileName, string str);                                        //Запись в файл

    string sha_1();                                                                     //Алгоритм преобразования
};
