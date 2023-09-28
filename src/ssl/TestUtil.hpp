// This file solely exists to define useful utility functions for
// SSL testing.
#ifndef INCLUDED_TESTUTIL_HPP
#define INCLUDED_TESTUTIL_HPP

#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "ssl/internal.h" // This contains the declaration for Array.

// This is stolen from
// https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/ssl/ssl_test.cc#L1199
static bssl::UniquePtr<X509> CertFromPEM(const char *pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, static_cast<int>(strlen(pem))));
  if (!bio) {
    return nullptr;
  }
  return bssl::UniquePtr<X509>(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

// This is stolen from
// https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/ssl/ssl_test.cc#L1208
static bssl::UniquePtr<EVP_PKEY> KeyFromPEM(const char *pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, static_cast<int>(strlen(pem))));
  if (!bio) {
    return nullptr;
  }
  return bssl::UniquePtr<EVP_PKEY>(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

// This is stolen from
// https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/ssl/ssl_test.cc#L1217
static bssl::UniquePtr<X509> GetTestCertificate() {
  static const char kCertPEM[] =
      "-----BEGIN CERTIFICATE-----\n"
      "MIICWDCCAcGgAwIBAgIJAPuwTC6rEJsMMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n"
      "BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n"
      "aWRnaXRzIFB0eSBMdGQwHhcNMTQwNDIzMjA1MDQwWhcNMTcwNDIyMjA1MDQwWjBF\n"
      "MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\n"
      "ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n"
      "gQDYK8imMuRi/03z0K1Zi0WnvfFHvwlYeyK9Na6XJYaUoIDAtB92kWdGMdAQhLci\n"
      "HnAjkXLI6W15OoV3gA/ElRZ1xUpxTMhjP6PyY5wqT5r6y8FxbiiFKKAnHmUcrgfV\n"
      "W28tQ+0rkLGMryRtrukXOgXBv7gcrmU7G1jC2a7WqmeI8QIDAQABo1AwTjAdBgNV\n"
      "HQ4EFgQUi3XVrMsIvg4fZbf6Vr5sp3Xaha8wHwYDVR0jBBgwFoAUi3XVrMsIvg4f\n"
      "Zbf6Vr5sp3Xaha8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQA76Hht\n"
      "ldY9avcTGSwbwoiuIqv0jTL1fHFnzy3RHMLDh+Lpvolc5DSrSJHCP5WuK0eeJXhr\n"
      "T5oQpHL9z/cCDLAKCKRa4uV0fhEdOWBqyR9p8y5jJtye72t6CuFUV5iqcpF4BH4f\n"
      "j2VNHwsSrJwkD4QUGlUtH7vwnQmyCFxZMmWAJg==\n"
      "-----END CERTIFICATE-----\n";
  return CertFromPEM(kCertPEM);
}

static bssl::UniquePtr<EVP_PKEY> GetTestKey() {
  static const char kKeyPEM[] =
      "-----BEGIN RSA PRIVATE KEY-----\n"
      "MIICXgIBAAKBgQDYK8imMuRi/03z0K1Zi0WnvfFHvwlYeyK9Na6XJYaUoIDAtB92\n"
      "kWdGMdAQhLciHnAjkXLI6W15OoV3gA/ElRZ1xUpxTMhjP6PyY5wqT5r6y8FxbiiF\n"
      "KKAnHmUcrgfVW28tQ+0rkLGMryRtrukXOgXBv7gcrmU7G1jC2a7WqmeI8QIDAQAB\n"
      "AoGBAIBy09Fd4DOq/Ijp8HeKuCMKTHqTW1xGHshLQ6jwVV2vWZIn9aIgmDsvkjCe\n"
      "i6ssZvnbjVcwzSoByhjN8ZCf/i15HECWDFFh6gt0P5z0MnChwzZmvatV/FXCT0j+\n"
      "WmGNB/gkehKjGXLLcjTb6dRYVJSCZhVuOLLcbWIV10gggJQBAkEA8S8sGe4ezyyZ\n"
      "m4e9r95g6s43kPqtj5rewTsUxt+2n4eVodD+ZUlCULWVNAFLkYRTBCASlSrm9Xhj\n"
      "QpmWAHJUkQJBAOVzQdFUaewLtdOJoPCtpYoY1zd22eae8TQEmpGOR11L6kbxLQsk\n"
      "aMly/DOnOaa82tqAGTdqDEZgSNmCeKKknmECQAvpnY8GUOVAubGR6c+W90iBuQLj\n"
      "LtFp/9ihd2w/PoDwrHZaoUYVcT4VSfJQog/k7kjE4MYXYWL8eEKg3WTWQNECQQDk\n"
      "104Wi91Umd1PzF0ijd2jXOERJU1wEKe6XLkYYNHWQAe5l4J4MWj9OdxFXAxIuuR/\n"
      "tfDwbqkta4xcux67//khAkEAvvRXLHTaa6VFzTaiiO8SaFsHV3lQyXOtMrBpB5jd\n"
      "moZWgjHvB2W9Ckn7sDqsPB+U2tyX0joDdQEyuiMECDY8oQ==\n"
      "-----END RSA PRIVATE KEY-----\n";
  return KeyFromPEM(kKeyPEM);
}

// This is taken from:
// https://github.com/google/boringssl/blob/955ef7991e41ac6c0ea5114b4b9abb98cc5fd614/ssl/ssl_test.cc#L1257
static bssl::UniquePtr<SSL_CTX>
CreateContextWithTestCertificate(const SSL_METHOD *method) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(method));
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  bssl::UniquePtr<EVP_PKEY> key = GetTestKey();
  if (!ctx || !cert || !key ||
      !SSL_CTX_use_certificate(ctx.get(), cert.get()) ||
      !SSL_CTX_use_PrivateKey(ctx.get(), key.get())) {
    return nullptr;
  }
  return ctx;
}

// Allow the importer to use this function in some situations too. Only
// useful in certain settings, hence it's opt in.
#ifdef SOCKET_SETUP
#include <atomic>
#include <thread>
// This just sets up two TLS connected sockets.
static bool setup_sockets(bssl::UniquePtr<SSL_CTX> &ctx,
                          std::unique_ptr<TLSSocket> &server,
                          std::unique_ptr<TLSSocket> &client) {

  server.reset(new TLSSocket{ctx.get()});
  uint16_t port;
  if (!server || !server->set_ip_v4() || !server->set_addr("127.0.0.1") ||
      !server->bind() || !server->listen(1) || !server->get_portnumber(&port)) {
    return false;
  }

  std::atomic<bool> worked = false;
  const auto server_join_code = [&]() {
    worked = server->accept() && server->do_handshake() == 1;
  };

  std::thread t(server_join_code);
  client.reset(new TLSSocket{ctx.get(), false});
  if (!client || !client->is_ssl_valid() || !client->set_ip_v4() ||
      !client->connect_to("127.0.0.1", port)) {
    t.join();
    return false;
  }

  t.join();
  return worked;
}

#endif
#endif
