#include "crypto/md5.hpp"
#include "crypto/sha1.hpp"
#include "crypto/sha256.hpp"
#include "crypto/sha3.hpp"
#include "crypto/crc32.hpp"
#include "crypto/keccak.hpp"

/*! AMXX Module */
#include "sdk/amxxmodule.h"

#include <algorithm>


namespace Crypto
{
	// native ModTuto_PrintMsg(const Message[], any:...);
	static auto Crypto_Hash(AMX* amx, cell* params) -> cell AMX_NATIVE_CALL;

	AMX_NATIVE_INFO Crypto_NativesInfo[] =
	{
		// { "Name", Function }

		{ "crypto_hash", Crypto_Hash },

		{ NULL, NULL } // Add this in the end.
	};
};