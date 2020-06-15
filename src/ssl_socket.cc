#include "../include/dmlc/logging.h"
#include "rabit/internal/ssl_context_manager.h"
#include "rabit/internal/ssl_socket.h"

namespace rabit {
namespace utils {

namespace {}  // namespace

bool SSLTcpSocket::ConfigureClientSSL() {
  int ret;
  mbedtls_x509_crt_init(&srvcert);
  mbedtls_x509_crt_init(&cachain);
  mbedtls_pk_init( &pkey );

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
    print_err(ret);
    return false;
  }

  if ((ret = mbedtls_ssl_config_defaults(
          &conf,
          MBEDTLS_SSL_IS_CLIENT,
          MBEDTLS_SSL_TRANSPORT_STREAM,
          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    print_err(ret);
    return false;
  }

  // TODO: Move out of critical path of connection
  char* cafile = (char*) SSLContextManager::instance()->get_ca_cert();
  if ((ret = mbedtls_x509_crt_parse_file( &cachain, cafile)) != 0) {
    print_err(ret);
    return false;
  }
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

  mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

  mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
  mbedtls_debug_set_threshold(DEBUG_LEVEL);

  // set up SSL context
  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    print_err(ret);
    return false;
  }
  return true;
}

bool SSLTcpSocket::ConfigureServerSSL() {
  int ret;
  mbedtls_x509_crt_init(&srvcert);
  mbedtls_x509_crt_init(&cachain);
  mbedtls_pk_init( &pkey );

  char* cafile = (char*) SSLContextManager::instance()->get_ca_cert();
  char* certfile = (char*) SSLContextManager::instance()->get_srv_cert();
  char* keyfile = (char*) SSLContextManager::instance()->get_pkey();

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
    print_err(ret);
    return false;
  }

  // TODO: Move out of critical path of connection
  if ((ret = mbedtls_x509_crt_parse_file( &srvcert, certfile)) != 0) {
    print_err(ret);
    return false;
  }
  if ((ret = mbedtls_x509_crt_parse_file( &cachain, cafile)) != 0) {
    print_err(ret);
    return false;
  }
  if((ret = mbedtls_pk_parse_keyfile( &pkey, keyfile, "")) != 0) {
    print_err(ret);
    return false;
  }

  mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);

  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
    print_err(ret);
    return false;
  }

  if ((ret = mbedtls_ssl_config_defaults(
          &conf,
          MBEDTLS_SSL_IS_SERVER,
          MBEDTLS_SSL_TRANSPORT_STREAM,
          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    print_err(ret);
    return false;
  }

  mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );

  mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
  mbedtls_debug_set_threshold(DEBUG_LEVEL);

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    print_err(ret);
    return false;
  }
  return true;
}

bool SSLTcpSocket::SSLHandshake() {
  int ret;
  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      print_err(ret);
      return false;
    }
  }
  return true;
}

bool SSLTcpSocket::SSLConnect(const SockAddr &addr) {
  if (Connect(addr)) {
    if (!ConfigureClientSSL())
      return false;

    net.fd = this->sockfd;
    this->SetBio();

    if(!SSLHandshake())
      return false;

    return true;
  }
  return false;
}

bool SSLTcpSocket::SSLAccept(SSLTcpSocket* client_sock) {
  SOCKET client_fd = Accept();

  client_sock->SetSocket(client_fd);
  int ret;

  if (!client_sock->ConfigureServerSSL())
    return false;

  client_sock->SetBio();

  if(!client_sock->SSLHandshake())
    return false;

  return true;
}

} /* namespace utils */
} /* namespace rabit */
