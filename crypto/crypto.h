#include "crypto/md5.hpp"
#include "sdk\amxxmodule.h"


namespace CryptoAMXX
{
	// native ModTuto_PrintMsg(const Message[], any:...);
	static auto CryptoAMXX_Hash(AMX* amx, cell* params) -> cell AMX_NATIVE_CALL;

	AMX_NATIVE_INFO CryptoAMXX_NativesInfo[] =
	{
		// { "Name", Function }

		{ "crypto_hash", CryptoAMXX_Hash },

		{ NULL, NULL } // Add this in the end.
	};
};