#ifndef L4PQC_IFACE_SHIM_H
#define L4PQC_IFACE_SHIM_H

#include "../l4pqc_rss.h"

#undef MAX_PROFILES
#undef NE_CRYPTO_WORKERS
#define MAX_PROFILES 1
#define NE_CRYPTO_WORKERS L4PQC_MAX_QUEUES
#define NE_FRAME L4PQC_FRAME

#endif
