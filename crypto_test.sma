#include <amxmodx>
#include <crypto>

public plugin_init() {
	register_clcmd("say /crypto", "cmdCrypto");
}

public cmdCrypto(id) {
	new iHash[256];
	crypto_hash("md5", "Test", szHash);
	
	client_print(id, print_chat, "%s", iHash);
}