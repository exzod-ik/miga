#pragma once

#include <windows.h>
#include "ProcessIdentityCache.h"

ProcessOwner LoadWindowsProcessIdentity(uint32_t processId);
