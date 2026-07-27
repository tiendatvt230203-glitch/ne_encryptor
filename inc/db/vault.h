#ifndef VAULT_H
#define VAULT_H

#define NE_VAULT_SECRET_PATH "kv/secret"

/* 1 = print kv/secret KEY=VALUE to stderr (debug). Set 0 before production. */
#define NE_VAULT_DEBUG_LOG 1

/* Unseal Vault (3 keys) and login using VAULT_* from NE_ENV_FILE.
 * Returns 0 on success or when Vault config is absent (skipped).
 * Returns -1 on failure. */
int ne_vault_unseal_and_login(void);

/* Fetch POSTGRES_* from Vault kv/secret into process environment.
 * Requires successful unseal/login first. Returns 0 on success. */
int ne_vault_load_secrets(void);

#endif
