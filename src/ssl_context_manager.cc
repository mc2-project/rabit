#include "rabit/internal/ssl_context_manager.h"
#include "../include/dmlc/logging.h"
#include <string>
#include <cstring>

namespace rabit {
namespace utils {

SSLContextManager::SSLContextManager() {
}

void SSLContextManager::LoadCertAndKey(const std::string certificate,
                                       const std::string private_key,
                                       const std::string trusted_ca_file) {
  srvcert = (char*) malloc (certificate.length() + 1);
  strcpy(srvcert, certificate.c_str());

  pkey = (char*) malloc (private_key.length() + 1);
  strcpy(pkey, private_key.c_str());

  cacert = (char*) malloc (trusted_ca_file.length() + 1);
  strcpy(cacert, trusted_ca_file.c_str());
}

}  // namespace utils
}  // namespace rabit
