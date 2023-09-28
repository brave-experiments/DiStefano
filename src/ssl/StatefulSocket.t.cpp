#include "../doctest.h"
#include "StatefulSocket.hpp"
#include <errno.h>

#include "openssl/bio.h"
#include <iostream>

//! [StatefulSocketInitialisationTests]
TEST_CASE("StatefulSocket initialisation tests") {
  //! [StatefulSocketInitialisesSSToZero]
  SUBCASE("Initialises memory to 0") {
    StatefulSocket fs;
    // Retrieves a const ref.
    const auto &ss = fs.get_ss();
    char zero_arr[sizeof(ss)];
    OPENSSL_memset(&zero_arr, 0, sizeof(zero_arr));
    // N.B no need to check for the sizes matching, as we use
    // the size of ss statically.
    CHECK(memcmp(zero_arr, &ss, sizeof(zero_arr)) == 0);
  }
  //! [StatefulSocketInitialisesSSToZero]

  //! [StatefulSocketIsServerByDefault]
  SUBCASE("Initialises to server by default") {
    StatefulSocket fs;
    CHECK(fs.is_server());
  }
  //! [StatefulSocketIsServerByDefault]

  //! [StatefulSocketClientByOptIn]
  SUBCASE("Must opt-in to being a client") {
    StatefulSocket fs{false};
    CHECK(!fs.is_server());
    CHECK(fs.is_client());
  }
  //! [StatefulSocketClientByOptIn]

  //! [StatefulSocketStartsUnbound]
  SUBCASE("Initialises as unbound") {
    StatefulSocket fs;
    CHECK(!fs.is_bound());
  }
  //! [StatefulSocketStartsUnbound]

  //! [StatefulSocketInitialisesToUnconnected]
  SUBCASE("Initialises as unconnected") {
    StatefulSocket fs;
    CHECK(!fs.is_connected());
  }
  //! [StatefulSocketInitialisesToUnconnected]

  //! [StatefulSocketInitialisesToInvalidConnection]
  SUBCASE("Initialises as invalid connection") {
    StatefulSocket fs;
    CHECK(!fs.is_connection_valid());
  }
  //! [StatefulSocketInitialisesToInvalidConnection]

  //! [StatefulSocketStartsAsNeither]
  SUBCASE("Initialises as neither ipv4 nor v6") {
    StatefulSocket fs;
    CHECK(!fs.is_ip_v4());
    CHECK(!fs.is_ip_v6());
  }
  //! [StatefulSocketStartsAsNeither]

  //! [StatefulSocketStartsInvalid]
  SUBCASE("Initialises with invalid socket") {
    StatefulSocket fs;
    CHECK(!fs.is_socket_valid());
  }
  //! [StatefulSocketStartsInvalid]

  //! [StatefulSocketInitialisesAddrEmpty]
  SUBCASE("Initialises with empty addr") {
    StatefulSocket fs;
    CHECK(fs.get_addr().empty());
  }
  //! [StatefulSocketInitialisesAddrEmpty]

  //! [StatefulSocketInitialisesWithoutValidAddress]
  SUBCASE("Starts without a valid address") {
    StatefulSocket fs;
    CHECK(!fs.has_valid_address());
  }
  //! [StatefulSocketInitialisesWithoutValidAddress]

  //! [StatefulSocketStartsNotListening]
  SUBCASE("Starts not in listening mode") {
    StatefulSocket fs;
    CHECK(!fs.is_listening());
  }
  //! [StatefulSocketStartsNotListening]

  //! [StatefulSocketStartsWithoutHostname]
  SUBCASE("Starts without valid hostname") {
    StatefulSocket fs;
    std::string out;
    CHECK(!fs.get_hostname(out));
  }
  //! [StatefulSocketStartsWithoutHostname]

  //! [StatefulSocketWriteFailsAtStart]
  SUBCASE("Write fails at start") {
    StatefulSocket fs;
    bssl::Array<uint8_t> arr;
    REQUIRE(arr.Init(10));
    CHECK(!fs.write(arr.data(), arr.size()));
  }
  //! [StatefulSocketWriteFailsAtStart]

  //! [StatefulSocketReadFailsAtStart]
  SUBCASE("Read fails at start") {
    StatefulSocket fs;
    bssl::Array<uint8_t> arr;
    REQUIRE(arr.Init(10));
    CHECK(fs.read(arr.data(), static_cast<int>(arr.size())) == -1);
  }
  //! [StatefulSocketReadFailsAtStart]

  //! [StatefulSocketAcceptFailsAtStart]
  SUBCASE("Accept fails at start") {
    StatefulSocket fs;
    CHECK(!fs.accept());
  }
  //! [StatefulSocketAcceptFailsAtStart]

  //! [StatefulSocketGetPortNumberFailsAtStart]
  SUBCASE("get_portnumber fails at start") {
    StatefulSocket fs;
    uint16_t out;
    CHECK(!fs.get_portnumber(&out));
  }
  //! [StatefulSocketGetPortNumberFailsAtStart]

  //! [StatefulSocketGetBioReturnsNullAtStart]
  SUBCASE("get_bio fails at start") {
    StatefulSocket fs;
    CHECK(fs.get_bio() == nullptr);
  }
  //! [StatefulSocketGetBioReturnsNullAtStart]
}
//! [StatefulSocketInitialisationTests]

//! [StatefulSocketFamilyTests]
TEST_CASE("StatefulSocket set family tests") {
  StatefulSocket fs;
  SUBCASE("Can't set the type as UNSPEC") { CHECK(!fs.set_family(AF_UNSPEC)); }

  SUBCASE("Can set the type to AF_INET4") { CHECK(fs.set_family(AF_INET)); }

  SUBCASE("Can set the type to AF_INET6") { CHECK(fs.set_family(AF_INET6)); }

  SUBCASE("Setting AF_INET sets ipv4") {
    REQUIRE(!fs.is_ip_v4());
    REQUIRE(fs.set_family(AF_INET));
    CHECK(fs.is_ip_v4());
  }

  SUBCASE("Setting AF_INET6 sets ipv6") {
    REQUIRE(!fs.is_ip_v6());
    REQUIRE(fs.set_family(AF_INET6));
    CHECK(fs.is_ip_v6());
  }

  SUBCASE("Can't be both v4 and v6") {
    REQUIRE(!fs.is_ip_v6());
    REQUIRE(!fs.is_ip_v4());
    REQUIRE(fs.set_family(AF_INET6));
    CHECK(fs.is_ip_v6());
    CHECK(!fs.is_ip_v4());
    REQUIRE(fs.set_family(AF_INET));
    CHECK(fs.is_ip_v4());
    CHECK(!fs.is_ip_v6());
  }
}
//! [StatefulSocketFamilyTests]

//! [StatefulSocketIsSocketValidTests]
TEST_CASE("StatefulSocket is_socket_valid Tests") {
  SUBCASE("Setting a type leads to a valid socket") {
    StatefulSocket fs;
    REQUIRE(!fs.is_socket_valid());
    REQUIRE(fs.set_family(AF_INET));
    CHECK(fs.is_socket_valid());
  }
}
//! [StatefulSocketIsSocketValidTests]

TEST_CASE("StatefulSocket set_ip Tests") {
  //! [StatefulSocketSetIpv4Tests]
  SUBCASE("Setting via set_ipv4 does the right thing") {
    StatefulSocket fs;
    REQUIRE(!fs.is_ip_v4());
    CHECK(fs.set_ip_v4());
    CHECK(fs.is_ip_v4());
  }
  //! [StatefulSocketSetIpv4Tests]

  //! [StatefulSocketSetIpv6Tests]
  SUBCASE("Setting via set_ipv6 does the right thing") {
    StatefulSocket fs;
    REQUIRE(!fs.is_ip_v6());
    CHECK(fs.set_ip_v6());
    CHECK(fs.is_ip_v6());
  }
  //! [StatefulSocketSetIpv6Tests]
}

//! [StatefulSocketSetAddrTests]
TEST_CASE("StatefulSocket set_addr Tests") {
  StatefulSocket fs;
  SUBCASE("Setting an ipv4 address tests") {
    REQUIRE(fs.set_ip_v4());

    //! [StatefulSocketInvalidAddressFail]
    SUBCASE("An invalid address fails") {
      CHECK(!fs.set_addr(""));
      CHECK(!fs.has_valid_address());
    }
    //! [StatefulSocketInvalidAddressFail]

    //! [StatefulSocketSetGetAddr]
    SUBCASE("A valid address succeeds") {
      CHECK(fs.set_addr("127.0.0.1"));
      CHECK(fs.get_addr() == "127.0.0.1");
      CHECK(fs.has_valid_address());
    }
    //! [StatefulSocketSetGetAddr]
  }

  SUBCASE("Setting an ipv6 address tests") {
    REQUIRE(fs.set_ip_v6());

    SUBCASE("An invalid address fails") {
      CHECK(!fs.set_addr(""));
      CHECK(!fs.has_valid_address());
    }

    SUBCASE("A valid address succeeds") {
      CHECK(fs.set_addr("::1"));
      CHECK(fs.get_addr() == "::1");
      CHECK(fs.has_valid_address());
    }
  }

  SUBCASE("Mixing address types fail") {
    SUBCASE("An invalid ipv6 address fails") {
      REQUIRE(fs.set_ip_v6());
      CHECK(!fs.set_addr("127.0.0.1"));
      CHECK(!fs.has_valid_address());
    }

    SUBCASE("An invalid ipv4 address fails") {
      REQUIRE(fs.set_ip_v4());
      CHECK(!fs.set_addr("::1"));
      CHECK(!fs.has_valid_address());
    }
  }
}
//! [StatefulSocketSetAddrTests]

//! [StatefulSocketBindTests]
TEST_CASE("StatefulSocket bind Tests") {
  StatefulSocket fs;
  SUBCASE("Bind fails without a set family") {
    REQUIRE(!fs.is_ip_v4());
    REQUIRE(!fs.is_ip_v6());
    CHECK(!fs.bind());
  }

  SUBCASE("Bind fails without a set address") {
    REQUIRE(fs.set_ip_v4());
    CHECK(!fs.bind());
    CHECK(!fs.is_bound());
    REQUIRE(fs.set_ip_v6());
    CHECK(!fs.bind());
    CHECK(!fs.is_bound());
  }

  SUBCASE("Bind succeeds with a family and an address") {
    REQUIRE(fs.set_ip_v4());
    REQUIRE(fs.set_addr("127.0.0.1"));
    CHECK(fs.bind());
    CHECK(fs.is_bound());
  }
}
//! [StatefulSocketBindTests]

//! [StatefulSocketCloseTests]
TEST_CASE("StatefulSocket close Tests") {
  StatefulSocket fs;
  SUBCASE("Close fails without valid socket") { CHECK(!fs.close()); }

  SUBCASE("Close succeeds on valid socket") {
    // Note that no address is needed.
    REQUIRE(fs.set_ip_v4());
    CHECK(fs.close());
    CHECK(!fs.is_bound());
    REQUIRE(fs.set_ip_v6());
    CHECK(fs.close());
    CHECK(!fs.is_bound());
  }

  SUBCASE("Close cannot be called twice in a row") {
    REQUIRE(fs.set_ip_v4());
    REQUIRE(fs.close());
    CHECK(!fs.close());
    CHECK(!fs.is_bound());
  }
}
//! [StatefulSocketCloseTests]

//! [StatefulSocketListenTests]
TEST_CASE("StatefulSocket listen Tests") {
  StatefulSocket fs;
  SUBCASE("Listen on unitialised socket fails") { CHECK(!fs.listen(1)); }
  SUBCASE("Listen on a client socket fails") {
    StatefulSocket fsc{false};
    CHECK(!fsc.listen(1));
  }

  REQUIRE(fs.set_family(AF_INET6));
  REQUIRE(fs.set_addr("::1"));
  if (!fs.bind()) {
    REQUIRE(fs.close());
    REQUIRE(fs.set_ip_v4());
    REQUIRE(fs.set_addr("127.0.0.1"));
    REQUIRE(fs.bind());
  }

  //! [StatefulSocketListeningFailsIfListenFails]
  SUBCASE("Listen with negative value fails") {
    CHECK(!fs.listen(-1));
    CHECK(!fs.is_listening());
  }
  //! [StatefulSocketListeningFailsIfListenFails]

  //! [StatefulSocketListens]
  SUBCASE("Listen with positive value succeeds") {
    CHECK(fs.listen(1));
    CHECK(fs.is_listening());
  }
  //! [StatefulSocketListens]
}
//! [StatefulSocketListenTests]

//! [StatefulSocketGetHostnameTests]
TEST_CASE("StatefulSocket get_hostname Tests") {
  StatefulSocket fs;
  std::string out;
  SUBCASE("Getting hostname on an unbound socket fails") {
    CHECK(!fs.get_hostname(out));
  }

  SUBCASE("Getting out a valid ipv6 address works") {
    // N.B this method is a bit hacky: we truncate the port number.
    // This is just the same as assuming that the port number is valid.
    REQUIRE(fs.set_family(AF_INET6));
    REQUIRE(fs.set_addr("::1"));
    REQUIRE(fs.bind());
    REQUIRE(fs.listen(1));
    CHECK(fs.get_hostname(out));
    // `out` is now formatted as [%s]:%d. We want the %s.
    // We know that [ is at position 0, so all we need to do is find the ]
    const auto right_bracket = out.find("]");
    REQUIRE(right_bracket != std::string::npos);
    // Warning: C++ requires you to specify the _size_ of the string
    // as the second argument here.
    // This is right_bracket - 1, because we're starting from 1.
    const auto addr = out.substr(1, right_bracket - 1);
    CHECK(addr == "::1");
    //! [StatefulSocketPortNumberv6]
    SUBCASE("Getting the port number works") {
      // We need to add 2 to eat the colon.
      const auto port_no =
          std::stoi(out.substr(right_bracket + 2, std::string::npos));
      uint16_t port_out;
      REQUIRE(fs.get_portnumber(&port_out));
      CHECK(port_no == port_out);
    }
    //! [StatefulSocketPortNumberv6]
  }

  SUBCASE("Getting out a valid ipv4 address works") {
    // N.B this method is a bit hacky: we truncate the port number.
    // This is just the same as assuming that the port number is valid.
    REQUIRE(fs.set_family(AF_INET));
    REQUIRE(fs.set_addr("127.0.0.1"));
    REQUIRE(fs.bind());
    REQUIRE(fs.listen(1));
    CHECK(fs.get_hostname(out));
    // In this case it's much easier. We just need to extract everything up to
    // the ":"
    const auto colon = out.find(":");
    REQUIRE(colon != std::string::npos);
    const auto addr = out.substr(0, colon);
    CHECK(addr == "127.0.0.1");

    //! [StatefulSocketPortNumberv4]
    SUBCASE("Getting the port number works") {
      const auto port_no = std::stoi(out.substr(colon + 1, std::string::npos));
      uint16_t port_out;
      REQUIRE(fs.get_portnumber(&port_out));
      CHECK(port_no == port_out);
    }
    //! [StatefulSocketPortNumberv4]
  }
}
//! [StatefulSocketGetHostnameTests]

//! [StatefulSocketGetPortNumberTests]
TEST_CASE("StatefulSocketGetPortNumber") {
  // N.B this test case is just meant to cover some pre-conditions.
  // Everything else is checked in StatefulSocketGetHostname.
  StatefulSocket client{false};
  StatefulSocket server;
  uint16_t out;

  SUBCASE("Can't get portnumber for client") {
    REQUIRE(client.is_client());
    CHECK(!client.get_portnumber(&out));
  }

  SUBCASE("Can't get portnumber for unbound socket") {
    REQUIRE(server.is_server());
    REQUIRE(!server.is_bound());
    CHECK(!server.get_portnumber(&out));
  }

  SUBCASE("Can't get portnumber with a null pointer as argument") {
    REQUIRE(server.set_ip_v4());
    REQUIRE(server.set_addr("127.0.0.1"));
    REQUIRE(server.bind());
    CHECK(!server.get_portnumber(nullptr));
  }
}
//! [StatefulSocketGetPortNumberTests]

//! [StatefulSocketAcceptTests]
TEST_CASE("StatefulSocketAcceptTests") {
  StatefulSocket fs;
  std::string out;
  static const char TestMessage[] = "test1234";

  SUBCASE("Accept fails if the socket isn't bound") {
    REQUIRE(!fs.is_bound());
    CHECK(!fs.accept());
  }

  SUBCASE("Accept fails on a client socket") {
    StatefulSocket fsc{false};
    CHECK(!fsc.accept());
  }

  SUBCASE("Accept fails if the socket isn't listening") {
    REQUIRE(fs.set_family(AF_INET));
    REQUIRE(fs.set_addr("127.0.0.1"));
    REQUIRE(fs.bind());
    CHECK(!fs.accept());
  }

  SUBCASE("Accept succeeds for ipv4") {
    REQUIRE(fs.set_family(AF_INET));
    REQUIRE(fs.set_addr("127.0.0.1"));
    REQUIRE(fs.bind());
    REQUIRE(fs.listen(1));
    REQUIRE(fs.get_hostname(out));
    REQUIRE(fs.is_socket_valid());
    // N.B here we use BoringSSL's BIO to make life a bit easier.
    bssl::UniquePtr<BIO> bio(BIO_new_connect(out.c_str()));
    REQUIRE(bio);
    const auto wrote_properly =
        BIO_write(bio.get(), TestMessage, sizeof(TestMessage));
    REQUIRE(wrote_properly == sizeof(TestMessage));
    CHECK(fs.accept());
  }

  SUBCASE("Accept succeeds for ipv6") {
    REQUIRE(fs.set_family(AF_INET6));
    REQUIRE(fs.set_addr("::1"));
    REQUIRE(fs.bind());
    REQUIRE(fs.listen(1));
    REQUIRE(fs.get_hostname(out));
    // N.B here we use BoringSSL's BIO to make life a bit easier.
    bssl::UniquePtr<BIO> bio(BIO_new_connect(out.c_str()));
    REQUIRE(bio);
    const auto wrote_properly =
        BIO_write(bio.get(), TestMessage, sizeof(TestMessage));
    REQUIRE(wrote_properly == sizeof(TestMessage));
    CHECK(fs.accept());
  }
}
//! [StatefulSocketAcceptTests]

//! [StatefulSocketReadWriteTests]
TEST_CASE("Reading and Writing tests") {
  StatefulSocket fs;
  std::string hostname;
  REQUIRE(fs.set_family(AF_INET));
  REQUIRE(fs.set_addr("127.0.0.1"));
  REQUIRE(fs.bind());
  REQUIRE(fs.listen(1));
  REQUIRE(fs.get_hostname(hostname));

  static const char TestMessage[] = "TestMessage";
  bssl::UniquePtr<BIO> bio(BIO_new_connect(hostname.c_str()));
  REQUIRE(bio);
  const auto wrote_properly =
      BIO_write(bio.get(), TestMessage, sizeof(TestMessage));
  REQUIRE(wrote_properly == sizeof(TestMessage));
  REQUIRE(fs.accept());

  SUBCASE("Reading tests") {
    char read_into[sizeof(TestMessage)];

    SUBCASE("Reading with len < 0 fails") {
      CHECK(fs.read(read_into, -1) == -1);
    }

    SUBCASE("Reading into a null buffer fails") {
      CHECK(fs.read(nullptr, 10) == -1);
    }

    SUBCASE("Reading into a regular buffer works") {
      const auto read_properly =
          fs.read(read_into, sizeof(read_into)) == sizeof(TestMessage);

      CHECK(read_properly);
      if (read_properly) {
        CHECK(memcmp(read_into, TestMessage, sizeof(TestMessage)) == 0);
      }
    }
  }

  SUBCASE("Writing tests") {
    char read_into[sizeof(TestMessage)];
    char socket_buff[sizeof(TestMessage)];
    // We'll read out to make sure that there's nothing "in the way"
    REQUIRE(fs.read(read_into, sizeof(read_into)) == sizeof(read_into));
    REQUIRE(memcmp(read_into, TestMessage, sizeof(TestMessage)) == 0);

    SUBCASE("Passing in a null buffer fails") { CHECK(!fs.write(nullptr, 0)); }

    SUBCASE("Passing in a valid buffer works") {
      CHECK(fs.write(read_into, sizeof(read_into)));
      REQUIRE(BIO_read(bio.get(), socket_buff, sizeof(socket_buff)));
      CHECK(memcmp(read_into, socket_buff, sizeof(TestMessage)) == 0);
    }
  }
}
//! [StatefulSocketReadWriteTests]

//! [StatefulSocketConnectToTests]
TEST_CASE("StatefulSocket connect_to Tests") {
  StatefulSocket client{false};
  StatefulSocket server;

  SUBCASE("Calling connect fails with empty address") {
    CHECK(!client.connect_to("", 100));
    CHECK(!client.is_connection_valid());
  }

  SUBCASE("Calling connect fails on a bound socket") {
    std::string out;
    SUBCASE("Calling connect fails on an IPv6 bound socket") {
      REQUIRE(server.set_family(AF_INET6));
      REQUIRE(server.set_addr("::1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      CHECK(!server.connect_to("::1", 100));
      CHECK(!server.is_connection_valid());
    }
    SUBCASE("Calling connect fails on an IPV4 bound socket") {
      REQUIRE(server.set_family(AF_INET));
      REQUIRE(server.set_addr("127.0.0.1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      CHECK(!server.connect_to("127.0.0.1", 100));
      CHECK(!server.is_connection_valid());
    }
  }

  SUBCASE("Calling connect fails if the type isn't set") {
    CHECK(!client.connect_to("127.0.0.1", 100));
    CHECK(!client.is_connected());
    CHECK(!client.is_connection_valid());
  }

  SUBCASE("Calling connect succeeds on a valid connection") {
    std::string out;
    SUBCASE("Ipv4") {
      REQUIRE(server.set_family(AF_INET));
      REQUIRE(server.set_addr("127.0.0.1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      // Split it around the :
      const auto colon = out.find(":");
      REQUIRE(colon != std::string::npos);
      const auto addr = out.substr(0, colon);
      REQUIRE(addr == "127.0.0.1");
      uint16_t port;
      REQUIRE(server.get_portnumber(&port));
      REQUIRE(client.set_ip_v4());
      CHECK(client.connect_to("127.0.0.1", port));
      CHECK(client.is_connected());
      CHECK(client.is_connection_valid());
    }

    SUBCASE("Ipv6") {
      REQUIRE(server.set_family(AF_INET6));
      REQUIRE(server.set_addr("::1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      // `out` is now formatted as [%s]:%d. We want the %s.
      // We know that [ is at position 0, so all we need to do is find the ]
      const auto right_bracket = out.find("]");
      REQUIRE(right_bracket != std::string::npos);
      // Warning: C++ requires you to specify the _size_ of the string
      // as the second argument here.
      // This is right_bracket - 1, because we're starting from 1.
      const auto addr = out.substr(1, right_bracket - 1);
      REQUIRE(addr == "::1");
      uint16_t port;
      REQUIRE(server.get_portnumber(&port));
      REQUIRE(client.set_ip_v6());
      CHECK(client.connect_to("::1", port));
      CHECK(client.is_connected());
      CHECK(client.is_connection_valid());
    }
  }

  SUBCASE("We can read and write between connected sockets") {
    std::string out;
    static const char TestMessage[] = "TestMessage";
    SUBCASE("Ipv4") {
      REQUIRE(server.set_family(AF_INET));
      REQUIRE(server.set_addr("127.0.0.1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      const auto colon = out.find(":");
      REQUIRE(colon != std::string::npos);
      const auto addr = out.substr(0, colon);
      CHECK(addr == "127.0.0.1");
      uint16_t port;
      REQUIRE(server.get_portnumber(&port));
      REQUIRE(client.set_ip_v4());
      REQUIRE(client.connect_to("127.0.0.1", port));
      // Now write the test message from the client.
      REQUIRE(client.write(TestMessage, sizeof(TestMessage)));
      CHECK(!server.is_connection_valid());
      REQUIRE(server.accept());
      CHECK(server.is_connection_valid());
      // Now we'll read it.
      char Message[sizeof(TestMessage)];
      auto read_correctly =
          server.read(Message, sizeof(Message)) == sizeof(TestMessage);
      CHECK(read_correctly);
      if (read_correctly) {
        CHECK(memcmp(Message, TestMessage, sizeof(TestMessage)) == 0);
      }

      // Now write it back
      REQUIRE(server.write(TestMessage, sizeof(TestMessage)));
      read_correctly =
          client.read(Message, sizeof(Message)) == sizeof(TestMessage);
      CHECK(read_correctly);
      if (read_correctly) {
        CHECK(memcmp(Message, TestMessage, sizeof(TestMessage)) == 0);
      }
    }

    SUBCASE("Ipv6") {
      REQUIRE(server.set_family(AF_INET6));
      REQUIRE(server.set_addr("::1"));
      REQUIRE(server.bind());
      REQUIRE(server.listen(1));
      REQUIRE(server.get_hostname(out));
      // `out` is now formatted as [%s]:%d. We want the %s.
      // We know that [ is at position 0, so all we need to do is find the ]
      const auto right_bracket = out.find("]");
      REQUIRE(right_bracket != std::string::npos);
      // Warning: C++ requires you to specify the _size_ of the string
      // as the second argument here.
      // This is right_bracket - 1, because we're starting from 1.
      const auto addr = out.substr(1, right_bracket - 1);
      REQUIRE(addr == "::1");
      uint16_t port;
      REQUIRE(server.get_portnumber(&port));
      REQUIRE(client.set_ip_v6());
      REQUIRE(client.connect_to("::1", port));
      // Now write the test message from the client.
      REQUIRE(client.write(TestMessage, sizeof(TestMessage)));
      CHECK(!server.is_connection_valid());
      REQUIRE(server.accept());
      CHECK(server.is_connection_valid());

      // Now we'll read it.
      char Message[sizeof(TestMessage)];
      auto read_correctly =
          server.read(Message, sizeof(Message)) == sizeof(TestMessage);
      CHECK(read_correctly);
      if (read_correctly) {
        CHECK(memcmp(Message, TestMessage, sizeof(TestMessage)) == 0);
      }

      // Now write it back
      REQUIRE(server.write(TestMessage, sizeof(TestMessage)));
      read_correctly =
          client.read(Message, sizeof(Message)) == sizeof(TestMessage);
      CHECK(read_correctly);
      if (read_correctly) {
        CHECK(memcmp(Message, TestMessage, sizeof(TestMessage)) == 0);
      }

      // ![StatefulSocketGetBioTests]
      SUBCASE("get_bio tests") {
        bssl::UniquePtr<BIO> bio(server.get_bio());
        // It isn't a nullptr on the firt call
        CHECK(bio.get() != nullptr);
        bio.reset(server.get_bio());
        // But on the second it will be
        CHECK(bio.get() == nullptr);
      }
      //! [StatefulSocketGetBioTests]
    }
  }
}
//! [StatefulSocketConnectToTests]
