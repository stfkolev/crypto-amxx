#if defined _crypto_included // Check if module/header is already included.
	#endinput // Exit.
#endif
#define _crypto_included // Declare that the module/header is included.

#pragma reqlib cryptoamxx // Require the module.
#if !defined AMXMODX_NOAUTOLOAD // Check if current AMXX (version/build) does not automatically load modules.
	#pragma loadlib cryptoamxx // Manually load the module.
#endif

native crypto_hash(const iHashType[], const iText[], const iResult[]);