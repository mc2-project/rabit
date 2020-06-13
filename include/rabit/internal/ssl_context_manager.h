#ifndef RABIT_SSL_CONTEXT_MANAGER_H_
#define RABIT_SSL_CONTEXT_MANAGER_H_

#include <memory>
#include <string>

#include "../include/dmlc/logging.h"
//#include "socket.h"

namespace rabit {
namespace utils {

constexpr int kSuccess = 1;

class SSLContextManager {
 public:

  SSLContextManager(const SSLContextManager &) = delete;
  SSLContextManager &operator=(const SSLContextManager &) = delete;

  static SSLContextManager *instance() {
    static SSLContextManager *manager = new SSLContextManager();
    return manager;
  }

  char* get_ca_cert() {
    return cacert;
  }

  char* get_pkey() {
    return pkey;
  }

  char* get_srv_cert() {
    return srvcert;
  }

  void LoadCertAndKey(const std::string certificate,
                      const std::string private_key,
                      const std::string trusted_ca_file);

 private:
  SSLContextManager();

  char* srvcert;
  char* pkey;
  char* cacert;
};

}  // namespace utils
}  // namespace rabit

#endif  // RABIT_SSL_CONTEXT_MANAGER_H_
