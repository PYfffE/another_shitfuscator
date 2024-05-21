// bytes_replacer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

int main(int argc, char* argv[])
{
    if (argc != 5) {
        std::cout << "Use replacer.exe path/to/inputfile length path/to/outputfile2 offset" "\n";
        return 1;
    }

    int input_length = atoi(argv[2]);
    int offset = atoi(argv[4]);
   

    FILE* infile, * outfile;
    errno_t err;



   

    // open input file
    err = fopen_s(&infile, argv[1], "rb");


    if (err == 0) std::cout << "The file " << argv[1] << " was opened\n";

    else
    {
        std::cout << "The file " << argv[1] << " was not opened\n";
        return 1;
    }


    fseek(infile, 0L, SEEK_END);
    int sz = ftell(infile);

    fclose(infile);

    // rewrite payoad size argument
    input_length = sz;

    err = fopen_s(&infile, argv[1], "rb");

    // open second file
    err = fopen_s(&outfile, argv[3], "rb+");
    if (err == 0) std::cout << "The file " << argv[3] << " was opened\n";

    else
    {
        std::cout << "The file " << argv[3] << " was not opened\n";
        return 1;
    }

    // go to offset
    err = fseek(outfile, offset, SEEK_SET);

    // read payload bytes
    char* payload = (char *) calloc(input_length, sizeof(char));

    //fgets(payload, input_length, infile);
    fread(payload, input_length, sizeof(char), infile);

    // std::cout << "payload: " << payload << "\n";

    fwrite(payload, input_length, sizeof(char), outfile);


    fclose(infile);
    fclose(outfile);

    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
