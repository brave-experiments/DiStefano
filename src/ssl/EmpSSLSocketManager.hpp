#ifndef INCLUDED_EMPSSLSOCKETMANAGER_HPP
#define INCLUDED_EMPSSLSOCKETMANAGER_HPP

/**
   EmpSSLSocketManagerManager.
   \brief This component realises a shared SSL socket that can be shared
across multiple threads. This component exists here to allow separation from the
EmpThreadSocket in client mode and in server mode.

Essentially, this component
allows the caller to setup a global socket that can be used exclusively in
client mode or exclusively in server mode. Notably, though, these cannot overlap
for threading reasons. As a result, we separate these sockets out here. In
practical terms this probably matters very little, but for testing purposes this
is a big win.

As a usage principle this namespace operates similarly to most C-style functions
for creating new objects. To instantiate a new ThreadSafeSocket, call the
appropriate create_ssl_ function. Similarly, to destroy a ThreadSafeSocket, call
the appropriate destroy_ssl_ function. The exact function you'll use depends on
the use case: if you don't want to make this decision, use the appropriate type
defined in EmpThreadSocket.hpp.
**/

struct ssl_st;             // Forward declaration for nicer compilation.
typedef struct ssl_st SSL; // N.B This has to be a typedef.
class ThreadSafeSSL;       // Forward declaration for nicer compilation.

namespace EmpSSLSocketManager {

/**
   create_ssl_client. This function creates a new global ThreadSafeSSL object
for use by clients. The underlying conneciton used is provided by the `ssl`
argument. This exists solely to allow all EmpThreadSockets to use the same SSL
connection. This function does not throw. Note that this function will
assert(false) if there is an already existing ThreadSafeSSL connection when this
function is called.
   @snippet EmpSSLSocketManager.t.cpp EmpSSLSocketManagerCreateSSL
   @param[in] ssl: the SSL connection to use. Must not be null.
**/
void create_ssl_client(SSL *const ssl) noexcept;

/**
 create_ssl_server. This function creates a new global ThreadSafeSSL object for
 use by servers. The underlying conneciton used is provided by the `ssl`
argument. This exists solely to allow all EmpThreadSockets to use the same SSL
connection. This function does not throw. Note that this function will
assert(false) if there is an already existing ThreadSafeSSL connection when this
function is called.
@snippet EmpSSLSocketManager.t.cpp EmpSSLSocketManagerCreateSSL
@param[in] ssl: the SSL connection to use. Must not be null.
**/
void create_ssl_server(SSL *const ssl) noexcept;

/**
   get_ssl_client. This function returns a pointer to the underlying client
   ThreadSafeSSL object. This function never returns a pointer that is null.
   This function does not throw and ideally should only be used during testing.
   @return a non-null pointer to the client's ThreadSafeSSL object.
 **/
ThreadSafeSSL *get_ssl_client() noexcept;

/**
 get_ssl_server. This function returns a pointer to the underlying server
 ThreadSafeSSL object. This function never returns a pointer that is null.
 This function does not throw and ideally should only be used during testing.
 @return a non-null pointer to the server's ThreadSafeSSL object.
**/
ThreadSafeSSL *get_ssl_server() noexcept;

/**
   destroy_ssl_server. This function destroys the underlying server
ThreadSafeSSL object. This function does not throw. Note that this function does
not free the underlying SSL connection.
   @snippet EmpSSLSocketManager.t.cpp EmpSSLSocketManagerDestroySSL
   @remarks This function nulls out the previous server ThreadSafeSSL object.
This is primarily for testing. Note that this should not be relied upon.
**/
void destroy_ssl_server() noexcept;

/**
 destroy_ssl_client. This function destroys the underlying client
ThreadSafeSSL object. This function does not throw. Note that this function does
not free the underlying SSL connection.
 @snippet EmpSSLSocketManager.t.cpp EmpSSLSocketManagerDestroySSL
 @remarks This function nulls out the previous client ThreadSafeSSL object. This
is primarily for testing. Note that this should not be relied upon.
**/
void destroy_ssl_client() noexcept;

/**
   register_new_socket_server. This function registers a new socket with the
   ThreadSafeSSL object for the server. This function does not throw. Note that
this function asserts that the underlying ThreadSafeSSL object is set for
safety.
   @snippet EmpSSLSocketManager.t.cpp EmpSSLSocketManagerRegisterNewSocket
   @return the tag for the new server socket.
**/
unsigned register_new_socket_server() noexcept;
/**
   register_new_socket_client. This function registers a new socket with the
   ThreadSafeSSL object for the client. This function does not throw. Note that
this function asserts that the underlying ThreadSafeSSL object is set for
safety.
   @snippet EmpSSLSocketManager.t.cpp EmpSSLSocketManagerRegisterNewSocket
   @return the tag for the new client socket.
**/
unsigned register_new_socket_client() noexcept;

} // namespace EmpSSLSocketManager

#endif
