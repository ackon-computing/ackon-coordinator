#include <string>

std::string sign(std::string raw);
bool verify(std::string plainText, char* sign, std::string publicKey);
