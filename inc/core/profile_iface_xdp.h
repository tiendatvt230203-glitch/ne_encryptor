#ifndef PROFILE_IFACE_XDP_H
#define PROFILE_IFACE_XDP_H

#include "xdp_attach.h"
#include "iface_reload.h"

typedef enum ne_iface_reload_mode profile_iface_xdp_reload_mode;

#define PROFILE_IFACE_XDP_ADD     NE_IFACE_RELOAD_ADD
#define PROFILE_IFACE_XDP_REMOVE  NE_IFACE_RELOAD_REMOVE
#define PROFILE_IFACE_XDP_DELTA   NE_IFACE_RELOAD_DELTA

#define profile_iface_xdp_prepare_init       ne_xdp_attach_prepare_init
#define profile_iface_xdp_attach_init        ne_xdp_attach_attach_init
#define profile_iface_xdp_bind_local         ne_xdp_attach_bind_local
#define profile_iface_xdp_bind_wan           ne_xdp_attach_bind_wan
#define profile_iface_xdp_detach_local       ne_xdp_attach_detach_local
#define profile_iface_xdp_detach_wan         ne_xdp_attach_detach_wan
#define profile_iface_xdp_detach_ifname      ne_xdp_attach_detach_ifname
#define profile_iface_xdp_detach_config      ne_xdp_attach_detach_config

#define profile_iface_xdp_can_add            ne_iface_reload_can_add
#define profile_iface_xdp_can_remove         ne_iface_reload_can_remove
#define profile_iface_xdp_can_delta          ne_iface_reload_can_delta
#define profile_iface_xdp_is_add_only        ne_iface_reload_is_add_only
#define profile_iface_xdp_apply_add          ne_iface_reload_apply_add
#define profile_iface_xdp_apply_remove       ne_iface_reload_apply_remove
#define profile_iface_xdp_apply_delta        ne_iface_reload_apply_delta
#define profile_iface_xdp_reload_impl        ne_iface_reload_impl
#define profile_iface_xdp_sync_wan_live      ne_iface_reload_sync_wan_live

#endif
