#include <amxmodx>
#include <crypto>

public plugin_init() {
	register_clcmd("say /crypto", "cmdCrypto");
}

public cmdCrypto(id) {
	new iHash[256];
	new iSuccess = crypto_hash("sha3", "Test", iHash);
	
	if(iSuccess == 0)
		client_print(id, print_chat, "Success: %s", iHash);
	else
		client_print(id, print_chat, "No Success: %d", iSuccess);
}