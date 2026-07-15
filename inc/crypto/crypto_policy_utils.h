#ifndef CRYPTO_POLICY_UTILS_H
#define CRYPTO_POLICY_UTILS_H

#include <stdint.h>
#include "config.h"


void crypto_apply_default_from_cfg(const struct app_config *cfg);


void crypto_apply_from_policy(const struct crypto_policy *cp);

#endif 

