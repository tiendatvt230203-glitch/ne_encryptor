#ifndef DB_PROFILE_CRUD_H
#define DB_PROFILE_CRUD_H

int ne_profile_create(const char *name, int bridge_enable, int *out_id);
int ne_profile_update(int id, const char *name, int bridge_enable, int has_name,
                      int has_bridge);
int ne_profile_delete(int id);
int ne_profile_list(void);

int ne_lan_add(int profile_id, const char *ifname);
int ne_lan_delete(int profile_id, const char *ifname);

int ne_wan_add(int profile_id, const char *ifname, const char *dst_ip, int weight);
int ne_wan_update(int profile_id, const char *ifname, const char *dst_ip, int weight,
                  int has_dst_ip, int has_weight);
int ne_wan_delete(int profile_id, const char *ifname);

#endif
