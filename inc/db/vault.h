#ifndef VAULT_H
#define VAULT_H

#define NE_VAULT_SECRET_PATH "kv/secret"

/*
 * Compile-time default for DB secret debug dump (0=off, 1=on).
 * Runtime override in /opt/SEP/be/.env: NE_VAULT_DEBUG=0|1
 * When on, logs POSTGRES_* pulled from Vault (for core↔BE pass mismatch checks).
 */
#ifndef NE_VAULT_DEBUG_LOG
#define NE_VAULT_DEBUG_LOG 0
#endif

int ne_vault_unseal_and_login(void);

int ne_vault_load_secrets(void);

#endif
