#ifndef VAULT_H
#define VAULT_H

#define NE_VAULT_SECRET_PATH "kv/secret"

#define NE_VAULT_DEBUG_LOG 0

int ne_vault_unseal_and_login(void);

int ne_vault_load_secrets(void);

#endif
