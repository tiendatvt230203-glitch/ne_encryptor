#ifndef DB_ENV_H
#define DB_ENV_H

#define NE_ENV_FILE "/opt/SEP/be/.env"
#define NE_STATE_DIR  "/var/lib/network-encryptor"

/* .env format (VAULT bootstrap only):
 *   VAULT_ADDR, VAULT_TOKEN, UNSEAL_KEY_1/2/3
 * POSTGRES_* are fetched from Vault kv/secret at runtime. */

struct ne_postgres_conn {
    const char *keywords[7];
    const char *values[7];
};

int load_ne_env(void);
int ne_postgres_conn_fill(struct ne_postgres_conn *out);
const char *resolve_db_password(void);
int parse_config_id_arg(const char *s, int *out);

#endif
