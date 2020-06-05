#ifndef RABIT_SSL_CONTEXT_MANAGER_H_
#define RABIT_SSL_CONTEXT_MANAGER_H_

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <memory>
#include <string>

#include "../include/dmlc/logging.h"
#include "socket.h"

namespace rabit {
namespace utils {

constexpr int kSuccess = 1;

class SSLContextManager {
 public:
  using AutoBIO = std::unique_ptr<BIO, decltype(&BIO_free)>;
  using AutoSSLContext = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

  SSLContextManager(const SSLContextManager &) = delete;
  SSLContextManager &operator=(const SSLContextManager &) = delete;

  static SSLContextManager *instance() {
    static SSLContextManager *manager = new SSLContextManager();
    return manager;
  }

  SSL_CTX *GetServerSSLCtx() {
    CHECK(server_ssl_ctx_.get() != nullptr);
    return server_ssl_ctx_.get();
  }

  SSL_CTX *GetClientSSLCtx() {
    CHECK(client_ssl_ctx_.get() != nullptr);
    return client_ssl_ctx_.get();
  }

  void LoadCertAndKey(const std::string &certificate,
                      const std::string &private_key,
                      const std::string &trusted_ca_file);
 private:
  SSLContextManager();

  // ssl context
  AutoSSLContext server_ssl_ctx_;
  AutoSSLContext client_ssl_ctx_;
  // certificate
  X509 *cert_ = nullptr;
  // matched private key
  EVP_PKEY *private_key_ = nullptr;
};

}  // namespace utils
}  // namespace rabit

#endif  // RABIT_SSL_CONTEXT_MANAGER_H_
