#include "crypto.h"

void OnAmxxAttach() {
	MF_AddNatives(Crypto::Crypto_NativesInfo);
}

void OnAmxxDetach() {
	// This function is necessary. Even if you have nothing to declare here.
	// This can be useful for clearing/destroying a handling system.
}

// There is no need to declare the function as static member.
// Just add the namespace and its certain function.
auto Crypto::Crypto_Hash(AMX* amx, cell* params) -> cell AMX_NATIVE_CALL {
	enum args {
		arg_count,
		arg_hashType,
		arg_string,
		arg_result
	};

	int stringLength(0), hashTypeLength(0);

	auto hashType = MF_GetAmxString(amx, params[arg_hashType], 0, nullptr);
	auto string = MF_GetAmxString(amx, params[arg_string], 1, nullptr);

	std::string checkHashType(hashType);

	/*! Transform to case-insensitive for comparison */
	std::transform(checkHashType.begin(), checkHashType.end(), checkHashType.begin(), ::tolower);

	/*! Compare if we have found the algorithm */
	if (checkHashType == "md5") {
		MD5 hash;

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];
		
		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	}
	else if (checkHashType == "sha1") {
		SHA1 hash;
		std::string iStringifiedText(string);

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	} else if (checkHashType == "sha256") {
		SHA256 hash;
		std::string iStringifiedText(string);

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	} else if (checkHashType == "sha3") {
		SHA3 hash;
		std::string iStringifiedText(string);

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	} else if (checkHashType == "crc32") {
		CRC32 hash;
		std::string iStringifiedText(string);

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	} else {
		std::string errMsg = "[" + std::string(MODULE_NAME) + "] Hash type '" + checkHashType + "' is not supported!\n";
		char* error = &errMsg[0];

		MF_PrintSrvConsole(error);

		return 1;
	}
	
	return -1;
}
