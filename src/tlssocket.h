/*!
 *  Copyright (c) 2014-2019 by Contributors
 * \file socket.h
 * \brief this file aims to provide a wrapper of sockets
 * \author Tianqi Chen
 */
#define __TLS__
#ifndef RABIT_INTERNAL_SOCKET_H_
#define RABIT_INTERNAL_SOCKET_H_
#include <string>
#include <cstring>
#include <vector>
#include <unordered_map>
#include "../include/rabit/internal/utils.h"
#include <iostream>

// mbedtls settings
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/certs.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"


#define DEBUG_LEVEL 1
#if defined(MBEDTLS_DEBUG_C) && DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

typedef int SOCKET;
typedef size_t sock_size_t;
//const int INVALID_SOCKET = -1;

#if defined(MBEDTLS_DEBUG_C) && DEBUG_LEVEL > 0
/**
 * Debug callback for mbedtls
 */
static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
  const char *p, *basename;
  (void) ctx;

  /* Extract basename from file */
  for (p = basename = file; *p != '\0'; p++) {
    if (*p == '/' || *p == '\\') {
      basename = p + 1;
    }
  }
  mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
}
#endif
/**
 *
 * Pretty print error codes thrown by mbedtls
 */
static void print_err(int error_code) {
  const size_t LEN = 2048;
  char err_buf[LEN];
  mbedtls_strerror(error_code, err_buf, LEN);
  mbedtls_printf(" ERROR: %s\n", err_buf);
}

namespace rabit {
namespace utils {
/*!
 * \brief base class containing common operations of TCP and UDP sockets
 */
class TLSConnection {
  public:
    /*! \brief the TLS wrapper of a socket */
    mbedtls_net_context net;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    bool created;
    int ret;

    virtual inline void Create() = 0;

    // default conversion to mbedtls context
    inline operator mbedtls_net_context() const {
      return net;
    }
    inline operator SOCKET() const {
      return net.fd;
    };
    /*!
     * \brief set this socket to use non-blocking mode
     * \param non_block whether set it to be non-block, if it is false
     *        it will set it back to block mode
     */
    inline void SetNonBlock(bool non_block) {
      if (!non_block) {
        mbedtls_net_set_block(&net);
      } else {
        mbedtls_net_set_nonblock(&net);
      }
    }

    /*!
     * \return last error of socket operation
     */
    inline static int GetLastError(void) {
      return errno;
    }
    /*! \return whether last error was would block */
    inline static bool LastErrorWouldBlock(void) {
      int errsv = GetLastError();
      return errsv == EAGAIN || errsv == EWOULDBLOCK;
    }
    /*! \brief get last error code if any */
    inline int GetSockError(void) const {
      int error = 0;
      socklen_t len = sizeof(error);
      if (net.fd != INVALID_SOCKET && getsockopt(net.fd,  SOL_SOCKET, SO_ERROR,
              reinterpret_cast<char*>(&error), &len) != 0) {
        Error("GetSockError");
      }
      return error;
    }
    /*! \brief check if anything bad happens */
    inline bool BadSocket(void) const {
      if (IsClosed()) return true;
      int err = GetSockError();
      return err == EBADF || err == EINTR;
    }
    inline void Close(void) {
      if (created) {
        // FIXME double free errors
        //mbedtls_net_free(&net);
        //mbedtls_ssl_free(&ssl);
        //mbedtls_ssl_config_free(&conf);
        //mbedtls_ctr_drbg_free(&ctr_drbg);
        //mbedtls_entropy_free(&entropy);
        net.fd = INVALID_SOCKET;
        created = false;
      } else {
        Error("Socket::Close double close the socket or close without create");
      }
    }
    /*! \brief check if socket is already closed */
    inline bool IsClosed(void) const {
      return !created;
    }
    // report an socket error
    inline static void Error(const char *msg) {
      int errsv = GetLastError();
      utils::Error("%d Socket %s Error:%s\n", getpid(), msg, strerror(errsv));
    }

    /*!
     * \brief decide whether the socket is at OOB mark
     * \return 1 if at mark, 0 if not, -1 if an error occured
     */
    inline int AtMark(void) const {
      int atmark;
      if (net.fd != INVALID_SOCKET && ioctl(net.fd, SIOCATMARK, &atmark) == -1) return -1;
      return atmark;
    }

    /*!
     * \brief send data using the socket
     * \param buf the pointer to the buffer
     * \param len the size of the buffer
     * \param flags extra flags
     * \return size of data actually sent
     *         return -1 if error occurs
     */
    inline ssize_t Send(const void *buf_, size_t len, int flag = 0) {
      const unsigned char *buf = reinterpret_cast<const unsigned char*>(buf_);
      ret = mbedtls_ssl_write(&ssl, buf, len);
      if (ret < 0) {
        print_err(ret);
        Error("Error: Sending");
      }
      return ret;
    }
    /*!
     * \brief receive data using the socket
     * \param buf_ the pointer to the buffer
     * \param len the size of the buffer
     * \param flags extra flags
     * \return size of data actually received
     *         return -1 if error occurs
     */
    inline ssize_t Recv(void *buf_, size_t len, int flags = 0) {
      unsigned char *buf = reinterpret_cast<unsigned char*>(buf_);
      ret = mbedtls_ssl_read(&ssl, buf, len);
      if (ret < 0) {
        print_err(ret);
        Error("Error: Receiving");
      }
      return ret;
    }
    /*!
     * \brief peform block write that will attempt to send all data out
     *    can still return smaller than request when error occurs
     * \param buf the pointer to the buffer
     * \param len the size of the buffer
     * \return size of data actually sent
     */
    inline size_t SendAll(const void *buf_, size_t len) {
      const unsigned char *buf = reinterpret_cast<const unsigned char*>(buf_);
      size_t ndone = 0;
      while (ndone < len) {
        ret = mbedtls_ssl_write(&ssl, buf, static_cast<size_t>(len - ndone));
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
          if (LastErrorWouldBlock()) return ndone;
          print_err(ret);
          Error("Error: SendAll");
        }
        buf += ret;
        ndone += ret;
      }
      return ndone;
    }
    /*!
     * \brief peforma block read that will attempt to read all data
     *    can still return smaller than request when error occurs
     * \param buf_ the buffer pointer
     * \param len length of data to recv
     * \return size of data actually sent
     */
    inline size_t RecvAll(void *buf_, size_t len) {
      unsigned char *buf = reinterpret_cast<unsigned char*>(buf_);
      size_t ndone = 0;
      while (ndone < len) {
        //mbedtls_printf("pid: %d ndone: %d len: %d. before ssl_read\n", getpid(), ndone, len);
        ret = mbedtls_ssl_read(&ssl, buf, static_cast<size_t>(len - ndone));
        //mbedtls_printf("pid: %d ndone: %d len: %d ret: %d. after ssl_read\n", getpid(), ndone, len, ret);
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
          print_err(ret);
          if (LastErrorWouldBlock()) return ndone;
          print_err(ret);
          Error("Error: RecvAll");
        }
        if (ret == 0) return ndone;
        buf += ret;
        ndone += ret;
      }
      return ndone;
    }
    /*!
     * \brief send a string over network
     * \param str the string to be sent
     */
    inline void SendStr(const std::string &str) {
      //LOG(INFO) << "SendStr " << str;
      int len = static_cast<int>(str.length());
      utils::Assert(this->SendAll(&len, sizeof(len)) == sizeof(len),
          "error during send SendStr");
      if (len != 0) {
        utils::Assert(this->SendAll(str.c_str(), str.length()) == str.length(),
            "error during send SendStr");
      }
      //LOG(INFO) << "Done sending str ";
    }
    /*!
     * \brief recv a string from network
     * \param out_str the string to receive
     */
    inline void RecvStr(std::string *out_str) {
      int len;
      utils::Assert(this->RecvAll(&len, sizeof(len)) == sizeof(len),
          "error during send RecvStr");
      out_str->resize(len);
      if (len != 0) {
        utils::Assert(this->RecvAll(&(*out_str)[0], len) == out_str->length(),
            "error during send SendStr");
      }
    }
};

class TLSClient : public TLSConnection {
 public:
  /*! \brief the TLS wrapper of a socket */
  mbedtls_x509_crt cacert;

  TLSClient(void) {
    created = false;
    this->Create();
  }

  /*! \brief close the socket */
  inline void Close(void) {
    if (created) {
      TLSConnection::Close();
      // FIXME free crt as well if loaded
    } else {
      Error("Socket::Close double close the socket or close without create");
    }
  }

  /*!
   * \brief create the socket, call this before using socket
   * \param af domain
   */
  inline void Create() override {
    // initialize all mbedTLS contexts
    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    created = true;
    // seeds and sets up entropy source
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
      print_err(ret);
      Error("Error: CTR_DRBG entropy source could not be seeded");
    }
  }

  /*!
   * \brief connect to an address
   * \param addr the address to connect to
   * \return whether connect is successful
   */
  inline bool Connect(const SockAddr &addr) {
    // Connect
    if ((ret = mbedtls_net_connect(&net, addr.AddrStr().c_str(),
        std::to_string(addr.port()).c_str(), MBEDTLS_NET_PROTO_TCP)) != 0) {
      print_err(ret);
      Error("Error: Could not connect");
    }
    // configure TLS layer
    if ((ret = mbedtls_ssl_config_defaults(&conf,
        MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
      print_err(ret);
      Error("Error: Could not configure TLS layer");
    }

    // FIXME add certificate auth (currently not verifying) 
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

    // configure RNG
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // enable debugging
#if defined(MBEDTLS_DEBUG_C) && DEBUG_LEVEL > 0
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    // set up SSL context
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
      print_err(ret);
      Error("Error: could not set up SSL");
    }

    // configure hostname
    // FIXME set hostname to check against cert
    //if ((ret = mbedtls_ssl_set_hostname(&ssl, addr.AddrStr().c_str())) != 0) {
    //  print_err(ret);
    //  Error("Error: Could not set hostname");
    //}
    // configure input/output functions for sending data
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    // perform handshake
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        print_err(ret);
        Error("Error: Failed handshake!");
      }
    }
    LOG(INFO) << "Connected!!";
    return true;
  }
};

class TLSServer : public TLSConnection {
  public:
    /*! \brief the TLS wrapper of a socket */
    mbedtls_net_context client_fd;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cachain;
    mbedtls_pk_context pkey;

    TLSServer(void) {
      created = false;
      this->Create();
    }

    /*!
     * \brief try bind the socket to host, from start_port to end_port
     * \param start_port starting port number to try
     * \param end_port ending port number to try
     * \return the port successfully bind to, return -1 if failed to bind any port
     */
    inline int TryBindHost(int start_port, int end_port) {
      // TODO(tqchen) add prefix check
      for (int port = start_port; port < end_port; ++port) {
        if (mbedtls_net_bind(&net, NULL, std::to_string(port).c_str(), MBEDTLS_NET_PROTO_TCP) == 0) {
          return port;
        }
        if (errno != EADDRINUSE) {
          Error("TryBindHost");
        }
      }
    
      return -1;
    }

    /*! \brief close the socket */
    inline void Close(void) {
      if (created) {
        TLSConnection::Close();
        // FIXME free crt as well if loaded
        // FIXME free cachain as well if loaded
        // FIXME free pk as well if loaded
        // FIXME free client_fd?

        created = false;
      } else {
        Error("Socket::Close double close the socket or close without create");
      }
    }

    /*!
     * \brief create the socket, call this before using socket
     * \param af domain
     */
    inline void Create() override {
      // initialize all mbedTLS contexts
      mbedtls_net_init(&net);
      mbedtls_net_init(&client_fd);
      mbedtls_ssl_init(&ssl);
      mbedtls_ssl_config_init(&conf);
      mbedtls_x509_crt_init(&srvcert);
      mbedtls_x509_crt_init(&cachain);
      mbedtls_ctr_drbg_init(&ctr_drbg);
      created = true;
      // seeds and sets up entropy source
      mbedtls_entropy_init(&entropy);
      if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
        print_err(ret);
        Error("Error: CTR_DRBG entropy source could not be seeded");
      }

      // FIXME currently using inbuilt certs / key
      ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt_ec, mbedtls_test_srv_crt_ec_len );
      if( ret != 0 ) {
          print_err(ret);
          Error("Error: Could not parse cert");
      }
      ret = mbedtls_x509_crt_parse( &cachain, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len );
      if( ret != 0 ) {
          print_err(ret);
          Error("Error: Could not parse CA chain");
      }
      mbedtls_pk_init( &pkey );
      ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key_ec, mbedtls_test_srv_key_ec_len, NULL, 0 );
      if( ret != 0 ) {
          print_err(ret);
          Error("Error: Could not parse key");
      }
      mbedtls_ssl_conf_ca_chain( &conf, &cachain, NULL );
      if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 ) {
        print_err(ret);
        Error("Error: Could not conf cert");
      }


      if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
        print_err(ret);
        Error("Error: Failed config");
      }
    }

    /*! \brief get a new connection */
    void Accept(TLSClient *conn) {
      mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );

      if( ( ret = mbedtls_net_accept( &net, &client_fd, NULL, 0, NULL ) ) != 0 ) {
        print_err(ret);
        Error( "Error: could not accept");
        //goto exit;
      }

      // Make sure memory refs are valid
      mbedtls_ssl_init( &ssl );
      if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        print_err(ret);
        Error("Error: could not set up SSL");
      }
      mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

      while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 ) {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
          print_err(ret);
          Error("Error: failed to do handshake while accepting");
        }
      }
      memcpy(&conn->net, &client_fd, sizeof(mbedtls_net_context));
      memcpy(&conn->ssl, &ssl, sizeof(mbedtls_ssl_context));
    }
};

/*! \brief helper data structure to perform poll */
}  // namespace utils
}  // namespace rabit
#endif  // RABIT_INTERNAL_SOCKET_H_
