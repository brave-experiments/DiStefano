#include <emp-tool/emp-tool.h>
#include "test/single_execution.h"
using namespace std;
using namespace emp;


int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
//	io->set_nodelay();
//
    // NIST test vector
    string input_message_key = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    string expected_output = "69C4E0D86A7B0430D8CDB78070B4C55A";

	test<NetIO>(party, io, circuit_file_location+"AES-non-expanded.txt", expected_output, input_message_key);
    //cout << "expected output: " << endl << hex_to_binary(expected_output) << endl;
	delete io;
	return 0;
}
