#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
using namespace std;
using namespace emp;

inline const char* hex_char_to_bin(char c) {
	switch(toupper(c)) {
		case '0': return "0000";
		case '1': return "0001";
		case '2': return "0010";
		case '3': return "0011";
		case '4': return "0100";
		case '5': return "0101";
		case '6': return "0110";
		case '7': return "0111";
		case '8': return "1000";
		case '9': return "1001";
		case 'A': return "1010";
		case 'B': return "1011";
		case 'C': return "1100";
		case 'D': return "1101";
		case 'E': return "1110";
		case 'F': return "1111";
		default: return "0";
	}
}

inline std::string hex_to_binary(std::string hex) {
	std::string bin;
	for(unsigned i = 0; i != hex.length(); ++i)
		bin += hex_char_to_bin(hex[i]);
	return bin;
}

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH)+string("bristol_format/");

template<typename T>
void test(int party, T* io, string name, string check_output = "", string hin = "") {
	//string file = circuit_file_location + name;
	string file = name;
	BristolFormat cf(file.c_str());
	auto t1 = clock_start();
	C2PC<T> twopc(io, party, &cf);
	io->flush();
	cout << "one time:\t"<<party<<"\t" <<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	cout << "inde:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	cout << "dep:\t"<<party<<"\t"<<time_from(t1)<<endl;

    bool *in; 
    bool *out;
    in = new bool[cf.n1 + cf.n2];
    out = new bool[cf.n3];
    if (hin.size() > 0) {
        string bin = hex_to_binary(hin);
        for (int i=0; i < cf.n1 + cf.n2; ++i) {
            if (bin[i] == '0') 
                in[i] = false;
            else if (bin[i] == '1') 
                in[i] = true;
            else {
                cout << "problem: " << bin[i] << endl;
                exit(1);
            }
        }
    } else {
        memset(in, false, cf.n1 + cf.n2);
    }
	memset(out, false, cf.n3);
	t1 = clock_start();
	twopc.online(in, out, true);
	cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;
    //cout << "actual output: " << endl;
    //for (int i=0; i < cf.n3; ++i)
        //cout << out[i];
    //cout << endl;
	if(check_output.size() > 0){
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
	}
	delete[] in;
	delete[] out;
}



