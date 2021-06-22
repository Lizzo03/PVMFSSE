#include "DistSSE.db_generator.h"


int main(int argc, char** argv) {
  // Instantiate the client and channel isn't authenticated
	
	if (argc < 3) {
		std::cerr<<"argc error"<<std::endl;	
		exit(-1);
	}

	size_t N_entry = atoi(argv[2]);
	std::string db_path = std::string(argv[1]);

std::cout << "update begin..." <<std::endl;

	DistSSE::gen_rdb(db_path, N_entry);

std::cout <<"update done." <<std::endl;

	
	
	return 0;
}

