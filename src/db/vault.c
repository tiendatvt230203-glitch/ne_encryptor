#include "../../inc/db/vault.h"
#include "../../inc/db/db_env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VAULT_CMD_BUF 2048
#define VAULT_VAL_BUF 2048

struct ne_vault_cfg {
    char addr[256];
    char token[256];
    char k1[256];
    char k2[256];
    char k3[256];
};

static void strip_env_quotes(char *val)
{
    size_t len = strlen(val);

    if (len >= 2 && val[0] == '"' && val[len - 1] == '"') {
        val[len - 1] = '\0';
        memmove(val, val + 1, len - 1);
        return;
    }
    if (len >= 2 && val[0] == '\'' && val[len - 1] == '\'') {
        val[len - 1] = '\0';
        memmove(val, val + 1, len - 1);
    }
}

static int ne_vault_key_allowed(const char *key)
{
    static const char *allowed[] = {
        "VAULT_ADDR",
        "VAULT_TOKEN",
        "UNSEAL_KEY_1",
        "UNSEAL_KEY_2",
        "UNSEAL_KEY_3",
        NULL
    };

    if (!key || !key[0])
        return 0;
    for (int i = 0; allowed[i]; i++) {
        if (strcmp(key, allowed[i]) == 0)
            return 1;
    }
    return 0;
}

static int ne_vault_load_cfg(struct ne_vault_cfg *cfg)
{
    FILE *fp;
    char line[2048];

    if (!cfg)
        return -1;

    memset(cfg, 0, sizeof(*cfg));

    fp = fopen(NE_ENV_FILE, "r");
    if (!fp) {
        fprintf(stderr, "[VAULT] Could not open: " NE_ENV_FILE "\n");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        char *eq;
        char *key;
        char *val;

        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '\n' || *p == '#')
            continue;

        eq = strchr(p, '=');
        if (!eq)
            continue;

        *eq = '\0';
        key = p;
        val = eq + 1;

        {
            char *end = key + strlen(key) - 1;
            while (end > key && (*end == ' ' || *end == '\t'))
                *end-- = '\0';
        }

        while (*val == ' ' || *val == '\t')
            val++;

        {
            size_t len = strlen(val);
            while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '\r'))
                val[--len] = '\0';
        }

        strip_env_quotes(val);

        if (!ne_vault_key_allowed(key) || !val[0])
            continue;

        if (strcmp(key, "VAULT_ADDR") == 0)
            strncpy(cfg->addr, val, sizeof(cfg->addr) - 1);
        else if (strcmp(key, "VAULT_TOKEN") == 0)
            strncpy(cfg->token, val, sizeof(cfg->token) - 1);
        else if (strcmp(key, "UNSEAL_KEY_1") == 0)
            strncpy(cfg->k1, val, sizeof(cfg->k1) - 1);
        else if (strcmp(key, "UNSEAL_KEY_2") == 0)
            strncpy(cfg->k2, val, sizeof(cfg->k2) - 1);
        else if (strcmp(key, "UNSEAL_KEY_3") == 0)
            strncpy(cfg->k3, val, sizeof(cfg->k3) - 1);
    }

    fclose(fp);

    if (cfg->addr[0])
        setenv("VAULT_ADDR", cfg->addr, 1);
    if (cfg->token[0])
        setenv("VAULT_TOKEN", cfg->token, 1);

    fprintf(stderr,
            "[VAULT] config from " NE_ENV_FILE
            " (addr=%s unseal_keys=%d token=%s)\n",
            cfg->addr[0] ? cfg->addr : "-",
            (cfg->k1[0] ? 1 : 0) + (cfg->k2[0] ? 1 : 0) + (cfg->k3[0] ? 1 : 0),
            cfg->token[0] ? "set" : "missing");

    return 0;
}

static int ne_vault_cfg_present(const struct ne_vault_cfg *cfg)
{
    return cfg && cfg->addr[0] && cfg->token[0] &&
           cfg->k1[0] && cfg->k2[0] && cfg->k3[0];
}

static int ne_vault_run_silent(const struct ne_vault_cfg *cfg, const char *cmd)
{
    char final_cmd[VAULT_CMD_BUF * 2];
    FILE *fp;
    int rc;

    snprintf(final_cmd, sizeof(final_cmd),
             "export VAULT_ADDR=\"%s\" VAULT_TOKEN=\"%s\" && %s > /dev/null 2>&1",
             cfg->addr, cfg->token, cmd);
    fp = popen(final_cmd, "r");
    if (!fp)
        return -1;
    rc = pclose(fp);
    return (rc == 0) ? 0 : -1;
}

static int ne_secret_metadata_key(const char *key)
{
    static const char *meta[] = {
        "created_time", "custom_metadata", "deletion_time", "destroyed", "version",
        NULL
    };

    if (!key)
        return 1;
    for (int i = 0; meta[i]; i++) {
        if (strcmp(key, meta[i]) == 0)
            return 1;
    }
    return 0;
}

static int ne_secret_key_wanted(const char *key)
{
    if (!key || !key[0])
        return 0;
    if (strncmp(key, "POSTGRES_", 9) == 0)
        return 1;
    if (strcmp(key, "LISTEN_PORT") == 0)
        return 1;
    return 0;
}

/* Parse "KEY    value" lines from `vault kv get` table output. */
static int ne_vault_parse_table_line(const char *line, char *key, size_t keysz,
                                     char *val, size_t valsz)
{
    const char *p = line;
    const char *val_start = NULL;
    size_t klen;

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0' || *p == '\n' || *p == '#')
        return -1;
    if (strncmp(p, "---", 3) == 0)
        return -1;

    for (const char *q = p; *q; q++) {
        if ((*q == ' ' && q[1] == ' ') || *q == '\t') {
            val_start = q;
            while (*val_start == ' ' || *val_start == '\t')
                val_start++;
            if (!*val_start || *val_start == '\n')
                continue;
            break;
        }
    }
    if (!val_start)
        return -1;

    klen = (size_t)(val_start - p);
    while (klen > 0 && (p[klen - 1] == ' ' || p[klen - 1] == '\t'))
        klen--;
    if (klen == 0 || klen >= keysz)
        return -1;

    memcpy(key, p, klen);
    key[klen] = '\0';

    strncpy(val, val_start, valsz - 1);
    val[valsz - 1] = '\0';

    {
        size_t n = strlen(val);
        while (n > 0 && (val[n - 1] == '\n' || val[n - 1] == '\r' ||
                         val[n - 1] == ' ' || val[n - 1] == '\t'))
            val[--n] = '\0';
    }

    strip_env_quotes(val);
    return val[0] ? 0 : -1;
}

static int ne_vault_value_needs_quotes(const char *key)
{
    if (!key)
        return 1;
    if (strcmp(key, "LISTEN_PORT") == 0 || strcmp(key, "POSTGRES_PORT") == 0)
        return 0;
    return 1;
}

static void ne_vault_log_kv(const char *key, const char *val)
{
#if NE_VAULT_DEBUG_LOG
    if (!key || !val)
        return;
    if (ne_vault_value_needs_quotes(key))
        fprintf(stderr, "%s=\"%s\"\n", key, val);
    else
        fprintf(stderr, "%s=%s\n", key, val);
#else
    (void)key;
    (void)val;
#endif
}

static void ne_vault_log_loaded_secrets(void)
{
#if NE_VAULT_DEBUG_LOG
    static const char *order[] = {
        "LISTEN_PORT",
        "POSTGRES_DB",
        "POSTGRES_PASSWORD",
        "POSTGRES_PORT",
        "POSTGRES_SERVER",
        "POSTGRES_USER",
        NULL
    };

    fprintf(stderr, "[VAULT] secrets from " NE_VAULT_SECRET_PATH ":\n");
    for (int i = 0; order[i]; i++) {
        const char *v = getenv(order[i]);
        if (v && v[0])
            ne_vault_log_kv(order[i], v);
    }
#endif
}

static int ne_vault_kv_get_and_apply(const struct ne_vault_cfg *cfg)
{
    char final_cmd[VAULT_CMD_BUF * 2];
    char line[4096];
    char key[128];
    char val[VAULT_VAL_BUF];
    FILE *fp;
    int loaded = 0;
    int rc;

    snprintf(final_cmd, sizeof(final_cmd),
             "export VAULT_ADDR=\"%s\" VAULT_TOKEN=\"%s\" && vault kv get %s",
             cfg->addr, cfg->token, NE_VAULT_SECRET_PATH);

    fp = popen(final_cmd, "r");
    if (!fp) {
        fprintf(stderr, "[VAULT] popen vault kv get failed\n");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (ne_vault_parse_table_line(line, key, sizeof(key), val, sizeof(val)) != 0)
            continue;
        if (ne_secret_metadata_key(key))
            continue;
        if (!ne_secret_key_wanted(key))
            continue;

        setenv(key, val, 1);
        loaded++;
    }

    rc = pclose(fp);
    if (loaded == 0) {
        fprintf(stderr, "[VAULT] vault kv get " NE_VAULT_SECRET_PATH
                " returned no POSTGRES_* fields (exit=%d)\n", rc);
        return -1;
    }
    if (rc != 0) {
        fprintf(stderr, "[VAULT] warn: vault kv get exit=%d but %d field(s) parsed\n",
                rc, loaded);
    }
    return 0;
}

static int ne_vault_verify_postgres_env(void)
{
    const char *host = getenv("POSTGRES_SERVER");
    const char *port = getenv("POSTGRES_PORT");
    const char *user = getenv("POSTGRES_USER");
    const char *dbname = getenv("POSTGRES_DB");
    const char *pass = getenv("POSTGRES_PASSWORD");

    if (!host || !host[0])
        host = getenv("POSTGRES_HOST");
    if ((!host || !host[0]) && getenv("POSTGRES_HOST"))
        setenv("POSTGRES_SERVER", getenv("POSTGRES_HOST"), 1);

    host = getenv("POSTGRES_SERVER");
    if (!host || !host[0])
        host = getenv("POSTGRES_HOST");

    if (!host || !host[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_SERVER in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    if (!port || !port[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_PORT in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    if (!user || !user[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_USER in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    if (!dbname || !dbname[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_DB in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    if (!pass || !pass[0]) {
        fprintf(stderr, "[VAULT] missing POSTGRES_PASSWORD in " NE_VAULT_SECRET_PATH "\n");
        return -1;
    }
    return 0;
}

int ne_vault_unseal_and_login(void)
{
    struct ne_vault_cfg cfg;
    char cmd[VAULT_CMD_BUF];
    int fail = 0;

    if (ne_vault_load_cfg(&cfg) != 0)
        return -1;

    if (!ne_vault_cfg_present(&cfg)) {
        fprintf(stderr,
                "[VAULT] missing VAULT_ADDR/TOKEN/UNSEAL_KEY_1/2/3 in "
                NE_ENV_FILE "\n");
        return -1;
    }

    fprintf(stderr, "[VAULT] unseal + login addr=%s\n", cfg.addr);

    snprintf(cmd, sizeof(cmd), "vault operator unseal \"%s\"", cfg.k1);
    if (ne_vault_run_silent(&cfg, cmd) != 0)
        fail = 1;

    snprintf(cmd, sizeof(cmd), "vault operator unseal \"%s\"", cfg.k2);
    if (ne_vault_run_silent(&cfg, cmd) != 0)
        fail = 1;

    snprintf(cmd, sizeof(cmd), "vault operator unseal \"%s\"", cfg.k3);
    if (ne_vault_run_silent(&cfg, cmd) != 0)
        fail = 1;

    snprintf(cmd, sizeof(cmd), "vault login \"%s\"", cfg.token);
    if (ne_vault_run_silent(&cfg, cmd) != 0)
        fail = 1;

    if (fail) {
        fprintf(stderr, "[VAULT] warn: unseal/login command failed\n");
        return -1;
    }

    fprintf(stderr, "[VAULT] unseal ok\n");
    return 0;
}

int ne_vault_load_secrets(void)
{
    struct ne_vault_cfg cfg;

    if (ne_vault_load_cfg(&cfg) != 0)
        return -1;

    if (!cfg.addr[0]) {
        fprintf(stderr, "[VAULT] missing VAULT_ADDR in " NE_ENV_FILE "\n");
        return -1;
    }

    fprintf(stderr, "[VAULT] vault kv get " NE_VAULT_SECRET_PATH "\n");

    if (ne_vault_kv_get_and_apply(&cfg) != 0)
        return -1;

    if (ne_vault_verify_postgres_env() != 0)
        return -1;

    ne_vault_log_loaded_secrets();
    fprintf(stderr, "[VAULT] POSTGRES_* loaded from " NE_VAULT_SECRET_PATH "\n");
    return 0;
}
