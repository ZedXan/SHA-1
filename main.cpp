#include "SHA-1.h"

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        cout << endl << "Использование: ./SHA-1 file_in" << endl << endl;

	return -1;
    }
    else
    {
        SHA_1 hash;

        if (!hash.read_file(argv[1]))
            cout << "Ошибка чтения файла!" << endl << endl;
        else if (!hash.write_file((char*)"SHA-1sum.txt", hash.sha_1()))
            cout << "Ошибка записи файла!" << endl << endl;
    }

    return 0;
}
