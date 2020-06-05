#ifndef RABIT_TLS_SOCKET_H_
#define RABIT_TLS_SOCKET_H_

#include "socket.h"
#include "ssl_context_manager.h"

namespace rabit {
namespace utils {

class SSLTcpSocket : public TCPSocket {
 public:
  using SharedSSL = std::shared_ptr<SSL>;

  // unique_ptr deleter got called only get() != nullptr.
  SSLTcpSocket() : TCPSocket(), ssl_() {}

  SSLTcpSocket(SOCKET sockfd) : TCPSocket(sockfd), ssl_() {}

  SSLTcpSocket(SOCKET sockfd, SharedSSL ssl) : TCPSocket(sockfd), ssl_(ssl) {}

  // Indicate has ssl context.
  bool HasSSL() const { return ssl_.get() != nullptr; }

  void SetSSL(SharedSSL ssl) {
    if (HasSSL()) {
      Socket::Error("Already has ssl.");
    }
    ssl_ = ssl;
  }

  // SSL Accept.
  SSLTcpSocket SSLAccept();

  // SSL Connect.
  bool SSLConnect(const SockAddr &addr);

  // SSL Write, note this does not support |flag| argument.
  ssize_t SSLSend(const void *buf, size_t len) {
    return SSL_write(ssl(), buf, len);
  }

  // SSL Read, note this does not support |flag| argument.
  ssize_t SSLRecv(void *buf, size_t len) { return SSL_read(ssl(), buf, len); }

  // SSL SendAll
  size_t SSLSendAll(const void *buf_, size_t len);

  // SSL RecvAll
  size_t SSLRecvAll(void *buf_, size_t len);

  /*!
   * \brief send a string over network
   * \param str the string to be sent
   */
  void SSLSendStr(const std::string &str) {
    int len = static_cast<int>(str.length());
    utils::Assert(this->SSLSendAll(&len, sizeof(len)) == sizeof(len),
                  "error during send SendStr");
    if (len != 0) {
      utils::Assert(this->SSLSendAll(str.c_str(), str.length()) == str.length(),
                    "error during send SendStr");
    }
  }

  /*!
   * \brief recv a string from network
   * \param out_str the string to receive
   */
  void SSLRecvStr(std::string *out_str) {
    int len;
    utils::Assert(this->SSLRecvAll(&len, sizeof(len)) == sizeof(len),
                  "error during send RecvStr");
    out_str->resize(len);
    if (len != 0) {
      utils::Assert(this->SSLRecvAll(&(*out_str)[0], len) == out_str->length(),
                    "error during send SendStr");
    }
  }

 private:
  SSL *ssl() { return ssl_.get(); }
  SharedSSL ssl_;
};

}  // namespace utils
}  // namespace rabit

#endif  // RABIT_TLS_SOCKET_H_
