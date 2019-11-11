#include "crypto.h"

void OnAmxxAttach() {
	MF_AddNatives(CryptoAMXX::CryptoAMXX_NativesInfo);
}

void OnAmxxDetach() {
	// This function is necessary. Even if you have nothing to declare here.
	// This can be useful for clearing/destroying a handling system.
}

// There is no need to declare the function as static member.
// Just add the namespace and its certain function.
auto CryptoAMXX::CryptoAMXX_Hash(AMX* amx, cell* params) -> cell AMX_NATIVE_CALL {

	enum args {
		arg_count,
		arg_hashType,
		arg_string,
		arg_result
	};
	int stringLength(0), hashTypeLength(0);

	auto hashType = MF_GetAmxString(amx, params[arg_hashType], 0, nullptr);
	auto string = MF_GetAmxString(amx, params[arg_string], 1, nullptr);

	if (!strcmp(hashType, "md5")) {
		char* errMsg = "";

		sprintf(errMsg, "Hash type %s is not supported!", hashType);
		MF_PrintSrvConsole(errMsg);

		return 1;
	}

	/*! Create Hash */
	MD5 hash;
	auto hashedString = hash(string, stringLength);

	MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

	return 0;
}
