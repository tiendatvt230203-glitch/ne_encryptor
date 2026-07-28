#ifndef IFACE_ROUTE_CLASSIFIER_H
#define IFACE_ROUTE_CLASSIFIER_H

#include "config.h"

int ne_iface_reload_can_add(const struct app_config *old, const struct app_config *new);
int ne_iface_reload_can_remove(const struct app_config *old, const struct app_config *new);
int ne_iface_reload_can_delta(const struct app_config *old, const struct app_config *new);
int ne_iface_reload_is_add_only(const struct app_config *old, const struct app_config *new);
int ne_iface_reload_is_edit_only(const struct app_config *old, const struct app_config *new);
int ne_iface_reload_any_predicate(const struct app_config *old, const struct app_config *new);

enum ne_iface_reload_path ne_iface_reload_classify(const struct app_config *old,
                                                   const struct app_config *new);

#endif
