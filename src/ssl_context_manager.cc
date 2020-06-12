#include "rabit/internal/ssl_context_manager.h"
#include "../include/dmlc/logging.h"

namespace rabit {
namespace utils {

SSLContextManager::SSLContextManager() {
  //  : server_ssl_ctx_(nullptr, SSL_CTX_free),
  //    client_ssl_ctx_(nullptr, SSL_CTX_free) {
  //SSL_library_init();
  //[> Load cryptos, et.al. <]
  //OpenSSL_add_all_algorithms();
  //[> Bring in and register error messages <]
  //SSL_load_error_strings();
  //[> Create new context <]
  //server_ssl_ctx_.reset(SSL_CTX_new(TLSv1_2_server_method()));
  //client_ssl_ctx_.reset(SSL_CTX_new(TLSv1_2_client_method()));
  //LOG(INFO) << "server_ssl_ctx_=" << server_ssl_ctx_.get()
  //          << ", client_ssl_ctx_=" << client_ssl_ctx_.get();
  //if (server_ssl_ctx_ == nullptr || client_ssl_ctx_ == nullptr) {
  //  Socket::Error("Cannot new ssl context");
  //}
}

void SSLContextManager::LoadCertAndKey(const std::string& certificate,
                                       const std::string& private_key,
                                       const std::string& trusted_ca_file) {
  //if (cert_ != nullptr || private_key_ != nullptr) {
  //  Socket::Error("already loaded");
  //}
  //AutoBIO bio(BIO_new_mem_buf(certificate.data(), certificate.size()),
  //            BIO_free);
  //cert_ = PEM_read_bio_X509(bio.get(), nullptr, 0, nullptr);
  //if (cert_ == nullptr) {
  //  Socket::Error("cannot load certificate");
  //}
  //AutoBIO bio_pkey(BIO_new_mem_buf(private_key.data(), private_key.size()),
  //                 BIO_free);
  //private_key_ = PEM_read_bio_PrivateKey(bio_pkey.get(), nullptr, nullptr, 0);
  //if (private_key_ == nullptr) {
  //  Socket::Error("cannot load certificate");
  //}
  //if (SSL_CTX_use_certificate(server_ssl_ctx_.get(), cert_) != kSuccess) {
  //  Socket::Error("cannot use certificate");
  //}
  //if (SSL_CTX_use_PrivateKey(server_ssl_ctx_.get(), private_key_) != kSuccess) {
  //  Socket::Error("cannot use PrivateKey");
  //}
  //if (SSL_CTX_check_private_key(server_ssl_ctx_.get()) != kSuccess) {
  //  Socket::Error("Check private key failed");
  //}
  //// Specify CAfile, set CApath as nullptr.
  //if (SSL_CTX_load_verify_locations(client_ssl_ctx_.get(),
  //                                  trusted_ca_file.c_str(),
  //                                  nullptr) != kSuccess) {
  //  Socket::Error("Cannot load root certificate for client.");
  //}
  //LOG(INFO) << "SSL_CTX initialized.";
  srvcert = certificate;
  pkey = private_key;
  cacert = trusted_ca_file;
}

}  // namespace utils
}  // namespace rabit
