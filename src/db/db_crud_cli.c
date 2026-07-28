#include "../../inc/db/db_crud_cli.h"
#include "../../inc/db/db_profile_crud.h"
#include "../../inc/db/db_env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int arg_value(int argc, char **argv, int i, const char **out)
{
    if (i + 1 >= argc) {
        fprintf(stderr, "[CRUD] missing value for %s\n", argv[i]);
        return -1;
    }
    *out = argv[++i];
    return i;
}

static int parse_profile_id_arg(const char *s, int *out_id)
{
    if (!s || !*s)
        return -1;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > 2147483647)
        return -1;
    *out_id = (int)v;
    return 0;
}

int ne_db_crud_cli_run(int argc, char **argv)
{
    if (argc < 2)
        return -1;

    const char *cmd = argv[1];
    int profile_id = 0;
    const char *ifname = NULL;
    const char *name = NULL;
    const char *dst_ip = NULL;
    int weight = 0;
    int has_weight = 0;
    int bridge_enable = 0;
    int has_bridge = 0;
    int has_name = 0;
    int has_dst_ip = 0;
    int rc;

    if (strcmp(cmd, "-profile-create") != 0 &&
        strcmp(cmd, "-profile-update") != 0 &&
        strcmp(cmd, "-profile-delete") != 0 &&
        strcmp(cmd, "-profile-list") != 0 &&
        strcmp(cmd, "-lan-add") != 0 &&
        strcmp(cmd, "-lan-del") != 0 &&
        strcmp(cmd, "-wan-add") != 0 &&
        strcmp(cmd, "-wan-update") != 0 &&
        strcmp(cmd, "-wan-del") != 0)
        return -1;

    if (load_ne_env() != 0) {
        fprintf(stderr, "[CRUD] DB env not loaded\n");
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-id") == 0) {
            const char *val;
            i = arg_value(argc, argv, i, &val);
            if (i < 0 || parse_profile_id_arg(val, &profile_id) != 0)
                return 1;
        } else if (strcmp(argv[i], "-if") == 0) {
            i = arg_value(argc, argv, i, &ifname);
            if (i < 0)
                return 1;
        } else if (strcmp(argv[i], "-name") == 0) {
            i = arg_value(argc, argv, i, &name);
            if (i < 0)
                return 1;
            has_name = 1;
        } else if (strcmp(argv[i], "-bridge-enable") == 0) {
            const char *val;
            i = arg_value(argc, argv, i, &val);
            if (i < 0)
                return 1;
            bridge_enable = atoi(val) != 0;
            has_bridge = 1;
        } else if (strcmp(argv[i], "-dst-ip") == 0) {
            i = arg_value(argc, argv, i, &dst_ip);
            if (i < 0)
                return 1;
            has_dst_ip = 1;
        } else if (strcmp(argv[i], "-weight") == 0) {
            const char *val;
            i = arg_value(argc, argv, i, &val);
            if (i < 0)
                return 1;
            weight = atoi(val);
            has_weight = 1;
        } else {
            fprintf(stderr, "[CRUD] unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    if (strcmp(cmd, "-profile-create") == 0) {
        int out_id = 0;
        if (!has_name) {
            fprintf(stderr, "[CRUD] -profile-create requires -name\n");
            return 1;
        }
        rc = ne_profile_create(name, bridge_enable, &out_id);
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "-profile-update") == 0) {
        if (profile_id <= 0) {
            fprintf(stderr, "[CRUD] -profile-update requires -id\n");
            return 1;
        }
        rc = ne_profile_update(profile_id, name, bridge_enable, has_name, has_bridge);
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "-profile-delete") == 0) {
        if (profile_id <= 0) {
            fprintf(stderr, "[CRUD] -profile-delete requires -id\n");
            return 1;
        }
        rc = ne_profile_delete(profile_id);
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "-profile-list") == 0) {
        rc = ne_profile_list();
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "-lan-add") == 0) {
        if (profile_id <= 0 || !ifname) {
            fprintf(stderr, "[CRUD] -lan-add requires -id and -if\n");
            return 1;
        }
        rc = ne_lan_add(profile_id, ifname);
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "-lan-del") == 0) {
        if (profile_id <= 0 || !ifname) {
            fprintf(stderr, "[CRUD] -lan-del requires -id and -if\n");
            return 1;
        }
        rc = ne_lan_delete(profile_id, ifname);
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "-wan-add") == 0) {
        if (profile_id <= 0 || !ifname) {
            fprintf(stderr, "[CRUD] -wan-add requires -id and -if\n");
            return 1;
        }
        if (!has_weight)
            weight = 0;
        rc = ne_wan_add(profile_id, ifname, dst_ip, weight);
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "-wan-update") == 0) {
        if (profile_id <= 0 || !ifname) {
            fprintf(stderr, "[CRUD] -wan-update requires -id and -if\n");
            return 1;
        }
        if (!has_dst_ip && !has_weight) {
            fprintf(stderr, "[CRUD] -wan-update requires -dst-ip and/or -weight\n");
            return 1;
        }
        rc = ne_wan_update(profile_id, ifname, dst_ip, weight, has_dst_ip, has_weight);
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "-wan-del") == 0) {
        if (profile_id <= 0 || !ifname) {
            fprintf(stderr, "[CRUD] -wan-del requires -id and -if\n");
            return 1;
        }
        rc = ne_wan_delete(profile_id, ifname);
        return rc == 0 ? 0 : 1;
    }

    return -1;
}
