#include "../../inc/db/db_profile_crud.h"
#include "../../inc/db/db_env.h"
#include "../../inc/core/xdp_validate.h"
#include "../../inc/core/config.h"

#include <libpq-fe.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static PGconn *crud_connect(void)
{
    struct ne_postgres_conn pg;

    if (ne_postgres_conn_fill(&pg) != 0)
        return NULL;
    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[CRUD] connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return NULL;
    }
    return conn;
}

static int crud_begin(PGconn *conn)
{
    PGresult *res = PQexec(conn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[CRUD] BEGIN failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

static int crud_commit(PGconn *conn)
{
    PGresult *res = PQexec(conn, "COMMIT");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[CRUD] COMMIT failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

static void crud_rollback(PGconn *conn)
{
    PGresult *res = PQexec(conn, "ROLLBACK");
    PQclear(res);
}

static int profile_exists_tx(PGconn *conn, int profile_id)
{
    char id_str[32];
    const char *params[1];
    PGresult *res;

    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    params[0] = id_str;
    res = PQexecParams(conn,
                       "SELECT 1 FROM ne_profiles WHERE id = $1",
                       1, NULL, params, NULL, NULL, 0);
    int ok = PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0;
    PQclear(res);
    return ok;
}

static int iface_owner_other_profile(PGconn *conn, int profile_id, const char *ifname)
{
    char pid_str[32];
    const char *params[2];
    PGresult *res;

    snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
    params[0] = ifname;
    params[1] = pid_str;
    res = PQexecParams(conn,
                       "SELECT profile_id FROM ne_lan WHERE interface = $1 AND profile_id != $2::int "
                       "UNION "
                       "SELECT profile_id FROM ne_wan WHERE interface = $1 AND profile_id != $2::int "
                       "LIMIT 1",
                       2, NULL, params, NULL, NULL, 0);
    int taken = PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0;
    if (taken) {
        fprintf(stderr,
                "[CRUD] %s: already used by profile %s\n",
                ifname, PQgetvalue(res, 0, 0));
    }
    PQclear(res);
    return taken;
}

static int profile_iface_count(PGconn *conn, int profile_id)
{
    char id_str[32];
    const char *params[1];
    PGresult *res;
    int n = 0;

    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    params[0] = id_str;
    res = PQexecParams(conn,
                       "SELECT (SELECT COUNT(*) FROM ne_lan WHERE profile_id = $1::int) + "
                       "(SELECT COUNT(*) FROM ne_wan WHERE profile_id = $1::int)",
                       1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0)
        n = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return n;
}

static int lan_row_exists(PGconn *conn, int profile_id, const char *ifname)
{
    char pid_str[32];
    const char *params[2];
    PGresult *res;
    int ok;

    snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
    params[0] = pid_str;
    params[1] = ifname;
    res = PQexecParams(conn,
                       "SELECT 1 FROM ne_lan WHERE profile_id = $1::int AND interface = $2",
                       2, NULL, params, NULL, NULL, 0);
    ok = PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0;
    PQclear(res);
    return ok;
}

static int wan_row_exists(PGconn *conn, int profile_id, const char *ifname)
{
    char pid_str[32];
    const char *params[2];
    PGresult *res;
    int ok;

    snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
    params[0] = pid_str;
    params[1] = ifname;
    res = PQexecParams(conn,
                       "SELECT 1 FROM ne_wan WHERE profile_id = $1::int AND interface = $2",
                       2, NULL, params, NULL, NULL, 0);
    ok = PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0;
    PQclear(res);
    return ok;
}

int ne_profile_create(const char *name, int bridge_enable, int *out_id)
{
    PGconn *conn;
    const char *params[2];
    char bridge_str[8];
    PGresult *res;
    int rc = -1;

    if (!name || !name[0] || !out_id)
        return -1;
    conn = crud_connect();
    if (!conn)
        return -1;
    if (crud_begin(conn) != 0)
        goto done;

    snprintf(bridge_str, sizeof(bridge_str), "%d", bridge_enable ? 1 : 0);
    params[0] = name;
    params[1] = bridge_str;
    res = PQexecParams(conn,
                       "INSERT INTO ne_profiles (name, bridge_enable) VALUES ($1, $2::bool) "
                       "RETURNING id",
                       2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        fprintf(stderr, "[CRUD] profile create failed: %s", PQerrorMessage(conn));
        PQclear(res);
        crud_rollback(conn);
        goto done;
    }
    *out_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    if (crud_commit(conn) != 0) {
        crud_rollback(conn);
        goto done;
    }
    fprintf(stderr, "[CRUD] profile created id=%d name=%s\n", *out_id, name);
    rc = 0;

done:
    PQfinish(conn);
    return rc;
}

int ne_profile_update(int id, const char *name, int bridge_enable, int has_name,
                      int has_bridge)
{
    PGconn *conn;
    PGresult *res;
    int rc = -1;

    if (id <= 0 || (!has_name && !has_bridge))
        return -1;
    conn = crud_connect();
    if (!conn)
        return -1;
    if (crud_begin(conn) != 0)
        goto done;
    if (!profile_exists_tx(conn, id)) {
        fprintf(stderr, "[CRUD] profile %d not found\n", id);
        crud_rollback(conn);
        goto done;
    }

    if (has_name && has_bridge) {
        char bridge_str[8];
        char id_str[32];
        const char *params[3];
        snprintf(bridge_str, sizeof(bridge_str), "%d", bridge_enable ? 1 : 0);
        snprintf(id_str, sizeof(id_str), "%d", id);
        params[0] = name;
        params[1] = bridge_str;
        params[2] = id_str;
        res = PQexecParams(conn,
                           "UPDATE ne_profiles SET name = $1, bridge_enable = $2::bool, "
                           "updated_at = NOW() WHERE id = $3::int",
                           3, NULL, params, NULL, NULL, 0);
    } else if (has_name) {
        char id_str[32];
        const char *params[2];
        snprintf(id_str, sizeof(id_str), "%d", id);
        params[0] = name;
        params[1] = id_str;
        res = PQexecParams(conn,
                           "UPDATE ne_profiles SET name = $1, updated_at = NOW() WHERE id = $2::int",
                           2, NULL, params, NULL, NULL, 0);
    } else {
        char id_str[32];
        char bridge_str[8];
        const char *params[2];
        snprintf(id_str, sizeof(id_str), "%d", id);
        snprintf(bridge_str, sizeof(bridge_str), "%d", bridge_enable ? 1 : 0);
        params[0] = bridge_str;
        params[1] = id_str;
        res = PQexecParams(conn,
                           "UPDATE ne_profiles SET bridge_enable = $1::bool, updated_at = NOW() "
                           "WHERE id = $2::int",
                           2, NULL, params, NULL, NULL, 0);
    }

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[CRUD] profile update failed: %s", PQerrorMessage(conn));
        PQclear(res);
        crud_rollback(conn);
        goto done;
    }
    PQclear(res);
    if (crud_commit(conn) != 0) {
        crud_rollback(conn);
        goto done;
    }
    fprintf(stderr, "[CRUD] profile %d updated\n", id);
    rc = 0;

done:
    PQfinish(conn);
    return rc;
}

int ne_profile_delete(int id)
{
    PGconn *conn;
    char id_str[32];
    const char *params[1];
    PGresult *res;
    int rc = -1;

    if (id <= 0)
        return -1;
    conn = crud_connect();
    if (!conn)
        return -1;
    if (crud_begin(conn) != 0)
        goto done;
    if (!profile_exists_tx(conn, id)) {
        fprintf(stderr, "[CRUD] profile %d not found\n", id);
        crud_rollback(conn);
        goto done;
    }
    snprintf(id_str, sizeof(id_str), "%d", id);
    params[0] = id_str;
    res = PQexecParams(conn, "DELETE FROM ne_profiles WHERE id = $1::int",
                       1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[CRUD] profile delete failed: %s", PQerrorMessage(conn));
        PQclear(res);
        crud_rollback(conn);
        goto done;
    }
    PQclear(res);
    if (crud_commit(conn) != 0) {
        crud_rollback(conn);
        goto done;
    }
    fprintf(stderr, "[CRUD] profile %d deleted\n", id);
    rc = 0;

done:
    PQfinish(conn);
    return rc;
}

int ne_profile_list(void)
{
    PGconn *conn;
    PGresult *res;
    int rc = -1;

    conn = crud_connect();
    if (!conn)
        return -1;
    res = PQexec(conn,
                 "SELECT id, name, bridge_enable FROM ne_profiles ORDER BY id");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CRUD] profile list failed: %s", PQerrorMessage(conn));
        PQclear(res);
        goto done;
    }
    fprintf(stderr, "[CRUD] profiles:\n");
    for (int i = 0; i < PQntuples(res); i++) {
        fprintf(stderr, "  id=%s name=%s bridge_enable=%s\n",
                PQgetvalue(res, i, 0),
                PQgetvalue(res, i, 1),
                PQgetvalue(res, i, 2));
    }
    PQclear(res);
    rc = 0;

done:
    PQfinish(conn);
    return rc;
}

int ne_lan_add(int profile_id, const char *ifname)
{
    PGconn *conn;
    char pid_str[32];
    const char *params[2];
    PGresult *res;
    int rc = -1;

    if (profile_id <= 0 || !ifname)
        return -1;
    if (ne_xdp_iface_preflight(ifname, "CRUD") != 0)
        return -1;

    conn = crud_connect();
    if (!conn)
        return -1;
    if (crud_begin(conn) != 0)
        goto done;
    if (!profile_exists_tx(conn, profile_id)) {
        fprintf(stderr, "[CRUD] profile %d not found\n", profile_id);
        crud_rollback(conn);
        goto done;
    }
    if (iface_owner_other_profile(conn, profile_id, ifname)) {
        crud_rollback(conn);
        goto done;
    }
    if (lan_row_exists(conn, profile_id, ifname)) {
        fprintf(stderr, "[CRUD] LAN %s already in profile %d\n", ifname, profile_id);
        crud_rollback(conn);
        goto done;
    }
    if (profile_iface_count(conn, profile_id) >= MAX_PROFILE_INTERFACES) {
        fprintf(stderr, "[CRUD] profile %d: MAX_PROFILE_INTERFACES reached\n", profile_id);
        crud_rollback(conn);
        goto done;
    }

    snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
    params[0] = pid_str;
    params[1] = ifname;
    res = PQexecParams(conn,
                       "INSERT INTO ne_lan (profile_id, interface) VALUES ($1::int, $2)",
                       2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[CRUD] lan add failed: %s", PQerrorMessage(conn));
        PQclear(res);
        crud_rollback(conn);
        goto done;
    }
    PQclear(res);
    if (crud_commit(conn) != 0) {
        crud_rollback(conn);
        goto done;
    }
    fprintf(stderr, "[CRUD] LAN %s added to profile %d\n", ifname, profile_id);
    rc = 0;

done:
    PQfinish(conn);
    return rc;
}

int ne_lan_delete(int profile_id, const char *ifname)
{
    PGconn *conn;
    char pid_str[32];
    const char *params[2];
    PGresult *res;
    int rc = -1;

    if (profile_id <= 0 || !ifname)
        return -1;
    conn = crud_connect();
    if (!conn)
        return -1;
    if (crud_begin(conn) != 0)
        goto done;
    if (!lan_row_exists(conn, profile_id, ifname)) {
        fprintf(stderr, "[CRUD] LAN %s not in profile %d\n", ifname, profile_id);
        crud_rollback(conn);
        goto done;
    }
    snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
    params[0] = pid_str;
    params[1] = ifname;
    res = PQexecParams(conn,
                       "DELETE FROM ne_lan WHERE profile_id = $1::int AND interface = $2",
                       2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[CRUD] lan delete failed: %s", PQerrorMessage(conn));
        PQclear(res);
        crud_rollback(conn);
        goto done;
    }
    PQclear(res);
    if (crud_commit(conn) != 0) {
        crud_rollback(conn);
        goto done;
    }
    fprintf(stderr, "[CRUD] LAN %s removed from profile %d\n", ifname, profile_id);
    rc = 0;

done:
    PQfinish(conn);
    return rc;
}

int ne_wan_add(int profile_id, const char *ifname, const char *dst_ip, int weight)
{
    PGconn *conn;
    char pid_str[32];
    char weight_str[16];
    const char *params[4];
    PGresult *res;
    int rc = -1;

    if (profile_id <= 0 || !ifname)
        return -1;
    if (weight < 0 || weight > 100)
        return -1;
    if (ne_xdp_iface_preflight(ifname, "CRUD") != 0)
        return -1;

    conn = crud_connect();
    if (!conn)
        return -1;
    if (crud_begin(conn) != 0)
        goto done;
    if (!profile_exists_tx(conn, profile_id)) {
        fprintf(stderr, "[CRUD] profile %d not found\n", profile_id);
        crud_rollback(conn);
        goto done;
    }
    if (iface_owner_other_profile(conn, profile_id, ifname)) {
        crud_rollback(conn);
        goto done;
    }
    if (wan_row_exists(conn, profile_id, ifname)) {
        fprintf(stderr, "[CRUD] WAN %s already in profile %d\n", ifname, profile_id);
        crud_rollback(conn);
        goto done;
    }
    if (profile_iface_count(conn, profile_id) >= MAX_PROFILE_INTERFACES) {
        fprintf(stderr, "[CRUD] profile %d: MAX_PROFILE_INTERFACES reached\n", profile_id);
        crud_rollback(conn);
        goto done;
    }

    snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
    snprintf(weight_str, sizeof(weight_str), "%d", weight);
    params[0] = pid_str;
    params[1] = ifname;
    params[2] = dst_ip && dst_ip[0] ? dst_ip : NULL;
    params[3] = weight_str;
    res = PQexecParams(conn,
                       "INSERT INTO ne_wan (profile_id, interface, dst_ip, weight) "
                       "VALUES ($1::int, $2, $3, $4::int)",
                       4, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[CRUD] wan add failed: %s", PQerrorMessage(conn));
        PQclear(res);
        crud_rollback(conn);
        goto done;
    }
    PQclear(res);
    if (crud_commit(conn) != 0) {
        crud_rollback(conn);
        goto done;
    }
    fprintf(stderr, "[CRUD] WAN %s added to profile %d\n", ifname, profile_id);
    rc = 0;

done:
    PQfinish(conn);
    return rc;
}

int ne_wan_update(int profile_id, const char *ifname, const char *dst_ip, int weight,
                  int has_dst_ip, int has_weight)
{
    PGconn *conn;
    PGresult *res;
    int rc = -1;

    if (profile_id <= 0 || !ifname || (!has_dst_ip && !has_weight))
        return -1;
    if (has_weight && (weight < 0 || weight > 100))
        return -1;

    conn = crud_connect();
    if (!conn)
        return -1;
    if (crud_begin(conn) != 0)
        goto done;
    if (!wan_row_exists(conn, profile_id, ifname)) {
        fprintf(stderr, "[CRUD] WAN %s not in profile %d\n", ifname, profile_id);
        crud_rollback(conn);
        goto done;
    }

    if (has_dst_ip && has_weight) {
        char pid_str[32];
        char weight_str[16];
        const char *params[4];
        snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
        snprintf(weight_str, sizeof(weight_str), "%d", weight);
        params[0] = dst_ip ? dst_ip : "";
        params[1] = weight_str;
        params[2] = pid_str;
        params[3] = ifname;
        res = PQexecParams(conn,
                           "UPDATE ne_wan SET dst_ip = $1, weight = $2::int "
                           "WHERE profile_id = $3::int AND interface = $4",
                           4, NULL, params, NULL, NULL, 0);
    } else if (has_dst_ip) {
        char pid_str[32];
        const char *params[3];
        snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
        params[0] = dst_ip ? dst_ip : "";
        params[1] = pid_str;
        params[2] = ifname;
        res = PQexecParams(conn,
                           "UPDATE ne_wan SET dst_ip = $1 "
                           "WHERE profile_id = $2::int AND interface = $3",
                           3, NULL, params, NULL, NULL, 0);
    } else {
        char pid_str[32];
        char weight_str[16];
        const char *params[3];
        snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
        snprintf(weight_str, sizeof(weight_str), "%d", weight);
        params[0] = weight_str;
        params[1] = pid_str;
        params[2] = ifname;
        res = PQexecParams(conn,
                           "UPDATE ne_wan SET weight = $1::int "
                           "WHERE profile_id = $2::int AND interface = $3",
                           3, NULL, params, NULL, NULL, 0);
    }

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[CRUD] wan update failed: %s", PQerrorMessage(conn));
        PQclear(res);
        crud_rollback(conn);
        goto done;
    }
    PQclear(res);
    if (crud_commit(conn) != 0) {
        crud_rollback(conn);
        goto done;
    }
    fprintf(stderr, "[CRUD] WAN %s updated in profile %d\n", ifname, profile_id);
    rc = 0;

done:
    PQfinish(conn);
    return rc;
}

int ne_wan_delete(int profile_id, const char *ifname)
{
    PGconn *conn;
    char pid_str[32];
    const char *params[2];
    PGresult *res;
    int rc = -1;

    if (profile_id <= 0 || !ifname)
        return -1;
    conn = crud_connect();
    if (!conn)
        return -1;
    if (crud_begin(conn) != 0)
        goto done;
    if (!wan_row_exists(conn, profile_id, ifname)) {
        fprintf(stderr, "[CRUD] WAN %s not in profile %d\n", ifname, profile_id);
        crud_rollback(conn);
        goto done;
    }
    snprintf(pid_str, sizeof(pid_str), "%d", profile_id);
    params[0] = pid_str;
    params[1] = ifname;
    res = PQexecParams(conn,
                       "DELETE FROM ne_wan WHERE profile_id = $1::int AND interface = $2",
                       2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[CRUD] wan delete failed: %s", PQerrorMessage(conn));
        PQclear(res);
        crud_rollback(conn);
        goto done;
    }
    PQclear(res);
    if (crud_commit(conn) != 0) {
        crud_rollback(conn);
        goto done;
    }
    fprintf(stderr, "[CRUD] WAN %s removed from profile %d\n", ifname, profile_id);
    rc = 0;

done:
    PQfinish(conn);
    return rc;
}
