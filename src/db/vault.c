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

static int ne_vault_get_field(const struct ne_vault_cfg *cfg, const char *field,
                              char *out, size_t outsz)
{
    char cmd[VAULT_CMD_BUF];
    char final_cmd[VAULT_CMD_BUF * 2];
    FILE *fp;
    size_t n;

    if (!cfg || !field || !out || outsz == 0)
        return -1;

    out[0] = '\0';

    snprintf(cmd, sizeof(cmd),
             "vault kv get -field=%s %s", field, NE_VAULT_SECRET_PATH);
    snprintf(final_cmd, sizeof(final_cmd),
             "export VAULT_ADDR=\"%s\" VAULT_TOKEN=\"%s\" && %s 2>/dev/null",
             cfg->addr, cfg->token, cmd);

    fp = popen(final_cmd, "r");
    if (!fp)
        return -1;

    if (!fgets(out, (int)outsz, fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';

    return out[0] ? 0 : -1;
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
    static const char *required[] = {
        "POSTGRES_SERVER",
        "POSTGRES_PORT",
        "POSTGRES_USER",
        "POSTGRES_DB",
        "POSTGRES_PASSWORD",
        NULL
    };
    char val[VAULT_VAL_BUF];
    int loaded = 0;

    if (ne_vault_load_cfg(&cfg) != 0)
        return -1;

    if (!cfg.addr[0]) {
        fprintf(stderr, "[VAULT] missing VAULT_ADDR in " NE_ENV_FILE "\n");
        return -1;
    }

    fprintf(stderr, "[VAULT] loading secrets from " NE_VAULT_SECRET_PATH "\n");

    for (int i = 0; required[i]; i++) {
        if (ne_vault_get_field(&cfg, required[i], val, sizeof(val)) != 0) {
            fprintf(stderr, "[VAULT] missing field: %s\n", required[i]);
            return -1;
        }
        setenv(required[i], val, 1);
        loaded++;
    }

    fprintf(stderr, "[VAULT] loaded %d secret field(s) into environment\n", loaded);
    return 0;
}
