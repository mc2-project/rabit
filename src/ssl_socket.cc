#include "rabit/internal/ssl_socket.h"
#include "../include/dmlc/logging.h"
#include "rabit/internal/ssl_context_manager.h"

namespace rabit {
namespace utils {

namespace {}  // namespace

bool SSLTcpSocket::SSLConnect(const SockAddr &addr) {
  LOG(INFO) << "SSLConnect to " << addr.AddrStr();
  if (Connect(addr)) {
    // Connect imply the client role.
    SetSSL(SharedSSL(SSL_new(SSLContextManager::instance()->GetClientSSLCtx()),
                     SSL_free));
    SSL_set_fd(ssl(), this->sockfd);
    int error_code;
    if ((error_code = SSL_connect(ssl())) != kSuccess) {
      LOG(ERROR) << "Cannot connect, SSL_get_error = "
                 << SSL_get_error(ssl(), error_code)
                 << ", addr: " << addr.AddrStr() << ":" << addr.port();
      Close();
      return false;
    } else {
      return true;
    }
  }
  LOG(ERROR) << "Cannot perform raw tcp connection to " << addr.AddrStr() << ":"
             << addr.port();
  return false;
}

SSLTcpSocket SSLTcpSocket::SSLAccept() {
  auto client_fd = Accept();
  // Accept implys the server role.
  SharedSSL ssl(SSL_new(SSLContextManager::instance()->GetServerSSLCtx()),
                SSL_free);
  SSL_set_fd(ssl.get(), client_fd.sockfd);
  int ssl_accept_code;
  if ((ssl_accept_code = SSL_accept(ssl.get())) != kSuccess) {
    int error_code = SSL_get_error(ssl.get(), ssl_accept_code);
    LOG(ERROR) << "SSL_get_error == " << error_code;
    Socket::Error("Cannot accept ssl socket");
  }
  return SSLTcpSocket(client_fd.sockfd, ssl);
}

size_t SSLTcpSocket::SSLSendAll(const void *buf_, size_t len) {
  const char *buf = reinterpret_cast<const char *>(buf_);
  size_t ndone = 0;
  while (ndone < len) {
    ssize_t ret = SSLSend(buf, static_cast<ssize_t>(len - ndone));
    if (ret == -1) {
      if (LastErrorWouldBlock() || BIO_should_retry(SSL_get_wbio(ssl())))
        return ndone;
      Socket::Error("SendAll");
    }
    buf += ret;
    ndone += ret;
  }
  return ndone;
}

size_t SSLTcpSocket::SSLRecvAll(void *buf_, size_t len) {
  char *buf = reinterpret_cast<char *>(buf_);
  size_t ndone = 0;
  while (ndone < len) {
    ssize_t ret = SSLRecv(buf, static_cast<sock_size_t>(len - ndone));
    if (ret == -1) {
      if (LastErrorWouldBlock() || BIO_should_retry(SSL_get_rbio(ssl())))
        return ndone;
      Socket::Error("RecvAll");
    }
    if (ret == 0) return ndone;
    buf += ret;
    ndone += ret;
  }
  return ndone;
}

} /* namespace utils */
} /* namespace rabit */
