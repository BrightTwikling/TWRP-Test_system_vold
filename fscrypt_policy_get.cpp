/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0
 */

#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <linux/fs.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <unistd.h>
#include <android-base/logging.h>

#include "fscrypt_policy.h"

extern "C" void bytes_to_hex(const uint8_t *bytes, size_t num_bytes, char *hex) {
    for (size_t i = 0; i < num_bytes; i++) {
        sprintf(&hex[2 * i], "%02x", bytes[i]);
    }
}

#ifdef USE_FSCRYPT_POLICY_V1
extern "C" bool fscrypt_policy_get_struct(
        const char *directory, struct fscrypt_policy_v1 *fep) {
#else
extern "C" bool fscrypt_policy_get_struct(
        const char *directory, struct fscrypt_policy_v2 *fep) {
#endif
    int fd = open(directory, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open directory " << directory;
        return false;
    }

#ifdef USE_FSCRYPT_POLICY_V1
    memset(fep, 0, sizeof(fscrypt_policy_v1));
#else
    memset(fep, 0, sizeof(fscrypt_policy_v2));
#endif

    struct fscrypt_get_policy_ex_arg ex_policy = {0};
    ex_policy.policy_size = sizeof(ex_policy.policy);

    if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, &ex_policy) != 0) {
        PLOG(ERROR) << "Failed to get encryption policy for " << directory;
        close(fd);
        return false;
    }

#ifdef USE_FSCRYPT_POLICY_V1
    memcpy(fep, &ex_policy.policy.v1, sizeof(ex_policy.policy.v1));
#else
    memcpy(fep, &ex_policy.policy.v2, sizeof(ex_policy.policy.v2));
#endif

    close(fd);
    return true;
}
