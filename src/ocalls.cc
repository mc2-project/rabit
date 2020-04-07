/*!
 *  Copyright (c) 2019 by Contributors
 * \file ocalls.cc
 * \author Rishabh Poddar, Chester Leung
 */

#include <xgboost/c_api.h>
#include <dmlc/io.h>

extern "C" {
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
}

#include <stdio.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>

#include "xgboost_u.h"

int host_rabit__GetRank() {
  LOG(DEBUG) << "Ocall: rabit::GetRank";
  return ocall_rabit__GetRank();
}

int host_rabit__GetWorldSize() {
  LOG(DEBUG) << "Ocall: rabit::GetWorldSize";
  return ocall_rabit__GetWorldSize();
}

int host_rabit__IsDistributed() {
  LOG(DEBUG) << "Ocall: rabit::IsDistributed";
  return ocall_rabit__IsDistributed();
}

