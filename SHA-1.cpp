#include "SHA-1.h"                                                                          //Подключаем описание класса

unsigned int SHA_1::F(unsigned int j, unsigned int x, unsigned int y, unsigned int z)       //Выбор битовой функции в соответсвии с номером цикла
{
    if (j < 20)                                                                     
        return (x & y) | ((~x) & z);                                                
    else if (j < 40)                                                                     
        return x ^ y ^ z;                                                           
    else if (j < 60)                                                                     
        return (x & y) | (x & z) | (y & z);                                         
    else if (j < 80)
        return x ^ y ^ z;
    else
        return 0;
}

bool SHA_1::read_file(char *fileName)                                                       //Чтение из файла
{
    ifstream in(fileName, ios::binary);                                                     //Открываем файл в бинарном режиме

    if (in.fail())                                                                          //Вернуть 0 
        return false;                                                                       //Если возникла ошибка

    in.seekg(0, ios::end);                                                                  //Подсчет
    int file_size = (int)in.tellg();                                                        //Размера
    in.seekg(0, ios::beg);                                                                  //Файла

    char *mas = new char[file_size];                                                        //Выделяем память под массив для считывания
    
    message.resize(file_size);                                                              //Меняем размер строки результата в соответствии с размером файла
    in.read(mas, file_size);                                                                //Считываем данные в массив
    in.close();                                                                             //Закрываем файл

    for (int i = 0; i < file_size; i++)                                                     //Перекидываем все данные
        message[i] = mas[i];                                                                //В строку, с которой далее будет работать алгоритм

    delete [] mas;                                                                          //Освобождаем память

    return true;                                                                            //Возвращаем 1 в случае успеха
}

bool SHA_1::write_file(char *fileName, string str)                                          //Запись в файл
{
    ofstream out(fileName);                                                                 //Открываем или создаем файл

    if (out.fail())                                                                         //Вернуть 0
        return false;                                                                       //Если возникла ошибка

    out << str;                                                                             //Записываем строку с результатом в файл

    return true;                                                                            //Возвращаем 1 в случае успеха
}

void SHA_1::extension()                                                                     //Шаг 1 - Расширение сообщения                                                    
{
    bitlen = message.size() * 8;                                                            //Исходная длина сообщения в битах (нужна для шага 2)

    message.push_back((unsigned char)0x80);                                                 //Добавляем в конец сообщения единичный бит

    while ((message.size() * 8) % 512 != 448)                                               //До тех пор, пока длина сообщения не станет равной 448 по модулю 512,
        message.push_back(0);                                                               //Заполняем сообщение нулями
}

void SHA_1::adding_length()                                                                 //Шаг 2 - Добавление длины сообщения                                                
{
    unsigned int temp = message.size();                                                     //Временная переменная для размера

    message.resize(temp + 8);                                                               //Изменяем размер сообщения на 8 байт(64 бита)

    for (unsigned int i = message.size() - 1; i >= temp; i--)                               //Добавляем длину исходного сообщения как целое 64-битное Big-endian число, в битах
    {
        message[i] = (unsigned char)bitlen;                                                 //Добавляем bitlen в сообщение

        bitlen >>= 8;                                                                       //Сдвигаем bitlen вправо на 8 бит
    }
}

void SHA_1::initialize_sha()                                                                //Шаг 3 - Инициализация SHA буфера
{
    H0 = 0x67452301;                                                                        //Инициализируем
    H1 = 0xEFCDAB89, H2 = 0x98BADCFE, H3 = 0x10325476, H4 = 0xC3D2E1F0;                     //Регистры

    K[0] = 0x5A827999, K[1] = 0x6ED9EBA1, K[2] = 0x8F1BBCDC, K[3] = 0xCA62C1D6;             //Инициализируем константы
}

void SHA_1::message_processing()                                                            //Шаг 4 - Обработка сообщения в блоках
{
    for (unsigned int i = 0; i < message.size(); i += 64)                                   //Цикл блоков сообщения
    {
        for (int k = 0; k < 64; k++)                                                        //Выделили блок сообщения равный 64 байтам(512 бит)
            M[k] = message[k + i];                                                          //Перекладываем в message 64 байта из text                                              

        for (int k = 0; k < 16; k++)                                                        //Формирование массива 32-битных слов
        {
            W[k] = ((unsigned int)M[k * 4]) << 24;                                          //По описанию алгоритма первые 16 элеметов message
            W[k] |= ((unsigned int)M[k * 4 + 1]) << 16;                                     //Просто перекладываются в W
            W[k] |= ((unsigned int)M[k * 4 + 2]) << 8;                                      //Единственное измение - это смена поряядка бит
            W[k] |= ((unsigned int)M[k * 4 + 3]);                                           //С little-endian на big-endian
        }

        for (int k = 16; k < 80; k++)                                                       //Остальные 64 элемента W
            W[k] = ROTATE_LEFT((W[k - 3] ^ W[k - 8] ^ W[k - 14] ^ W[k - 16]), 1);           //Получаются по этой формуле 

        A = H0; B = H1; C = H2; D = H3; E = H4;                                             //Сохраняем значения значения регистров на каждом этапе цикла

        //Магия
        for (int i = 0; i < 80; i++)                                                        
        {
            T = ROTATE_LEFT(A, 5) + F(i, B, C, D) + E + W[i] + K[i / 20];                    
            E = D;                                                                          
            D = C;                                                                                                                                                             
            C = ROTATE_LEFT(B, 30);                                                         
            B = A;                                                                          
            A = T;                                                                          
        }
        //Конец магии

        H0 += A; H1 += B; H2 += C; H3 += D; H4 += E;                                        //Обновляем значения регистров на каждом этапе цикла
    }
}

string SHA_1::sha_1()                                                                       //Алгоритм преобразования
{
    extension();                                                                            //Шаг 1 - Расширение сообщения 

    adding_length();                                                                        //Шаг 2 - Добавление длины сообщения

    initialize_sha();                                                                       //Шаг 3 - Инициализация SHA буфера
    
    message_processing();                                                                   //Шаг 4 - Обработка сообщения в блоках

    result << hex << H0 << H1 << H2 << H3 << H4;                                            //Шаг 5 - Результат в виде хэш-сообщения

    return result.str();                                                                    //Возвращаем результат в виде хэш-сообщения
}
