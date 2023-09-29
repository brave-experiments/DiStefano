# Src
This directory contains all of the code for this project.

## Requirements
- [cmake 3.5](https://cmake.org/)(required for BoringSSL).
- A recent version of [Perl](https://www.perl.org/) (required for BoringSSL).
- A recent version of [Go](https://go.dev/) (required for BoringSSL).
- OpenSSL
- (Optional) [Doxygen](https://doxygen.nl/) for generating documentation.
- (Optional) A copy of [Google Benchmark](https://github.com/google/benchmark). You can obtain this
  by simply running ```git clone https://github.com/google/benchmark.git``` in this directory. Note
  that you need this project to run benchmarks.

The method for installing these will depend on your operating system.
Please note that we do not support Windows at present: this is due to some limitations of how
socket libraries have been built historically.

## Warning
Please note that this library has not been subjected to a security audit and as a result it should only be considered
as a proof-of-concept research artefact. The authors of this code give absolutely no guarantees about the security properties
of this code: whilst we have tried our best to make sure that the code here follows strong engineering principles and realises
the MPC protocols in our work securely, mistakes can happen and underlying libraries can be faulty. We recommend that any
individual or organisation wishing to use this code engage in a thorough security audit.


## Building
You can build this project by running:

```
mkdir build
cd build
cmake ..
make
```

If this goes through successfully, you can test the project by running:

```bash
ctest -j # Optional number of threads to use
```

### Changing the compiler
You may wish to specify a particular compiler to use. To do that, invoke cmake as follows:

```bash
cmake -DCMAKE_CXX_COMPILER=<name of the compiler you want> ../
```

For example, if you want to force cmake to use clang, then you would write:

```bash
cmake -DCMAKE_CXX_COMPILER=clang++ ../
```

## File extensions and meanings
We follow a standardised layout for files to make it easy to discern what the purpose of a particular
file is. Our naming convention is somewhat inspired by [Lakos20], but with a few tweaks.

1. Declarations are placed in ```.hpp``` files. These declarations must not contain any code: they
   are strict declarations.  In some limited contexts (e.g templated constructors) we do allow both definitions
   and declarations to be in the same file.
2. Inline definitions are placed in ```.inl``` files. This usage should be restricted to templates
   or ```constexpr``` functions.
3. Definitions are placed in ```.cpp``` files. This is where the code actually lives.
4. Tests are placed in ```.t.cpp``` files.
5. Benchmarks (if applicable) are placed in ```.b.cpp``` files.


## Testing
We like tests. They're good and important for stability. We use the
[doctest](https://github.com/doctest/doctest) library for our unit tests, as they're
minimally invasive. We also test in both debug and release mode.

Where appropriate, each function has a series of tests in a separate file with the extension
```.t.cpp```. As with the previous section, this concretely means that:


1. We have a declaration in a ```.hpp``` file.
2. We have a definition in a ```.cpp``` file.
3. We have tests in a ```.t.cpp``` file.

For example, if we have this function declaration:

```c++
// In "do_something.hpp"
// A very useful function that does something vital.
void do_something();
```

Then we will have the definition in the corresponding ```.cpp``` file:

```c++
// In "do_something.cpp"
void do_something() {
    ...
}
```

And tests in the corresponding ```.t.cpp``` file:

```c++
// In "do_something.t.cpp"
TEST_CASE("do_something does something") {
  ...
}
```

Each test executable ends in ```Tests```. Extending the example from above, the output test
executables would be called ```DoSomethingDebugTests``` and ```DoSomethingOptTests```.


### A super brief guide to doctest's macros
Doctest uses a variety of C-style macros to express intent when it comes to test outcomes. Since
this might be confusing to someone who isn't familiar with the library, we'll briefly describe
the macros used here.

- ```TEST_CASE```. This macro sets up an anonymous function for executing test code. You can view
  this as essentially declaring a new function that doctest will pick up and execute when it runs.
  For example, if you were to declare a test function manually, you might write this:

  ```c++
  void test_my_function() {...}
  ```

  Whereas using doctest you'd write:

  ```c++
  TEST_CASE("test_my_function") {...}
  ```
- ```SUBCASE```. This macro declares a subtest inside an already existing test case. One important
  thing to know is that subtests are executed independently of each other. For example, if we had
  a test case that contained two sub cases (e.g 1 and 2) then doctest would run the test case twice:
  once executing test case 1, and once executing test case 2. This makes it substantially easier
  to set up a starting state.

- ```REQUIRE```. This macro is equivalent to C's ```assert``` macro. More precisely, if ```REQUIRE(x) == false``` for some binary predicate ```x```, then doctest marks the currently executing test as failed and aborts the run. This is useful if you're e.g checking the size of an array before iterating over it.
- ```CHECK```. This macro is equivalent to an ```if``` statement. If a ```CHECK``` fails, then the
  test will continue to run, but the error will be reported to the user.

### Running tests
To run the tests, simply type:

```bash
ctest
```

In the ```build``` directory. This will run both the debug and release tests. This should take
around 10 seconds.

To make life easier when it comes to running tests, we build our tests individually. You can
find a list of them in the ```build``` directory after you run ```make```. Thus, if a test failure
occurs, you can simply run the individual test as if it were a normal program. For example, if
```SSLOptTests``` were to fail, you can run this test as:

```bash
./SSLOptTests
```

If the tests take too long for you, then you can speed this up by running tests in parallel:

```bash
ctest -j #Optional number of threads to use
```

## Benchmarking

Benchmarking is a rather subtle and technical subject. To avoid diving too much into this debate,
we simply provide some microbenchmarks that should make it easier to debug some (but not all) performance issues if they occur.

These benchmarks can be found in the ```benchmarks``` directory. To speed-up compile time, these files are not compiled by default. If you
do want to compile these, then run `cmake` as follows:

```shell
cmake ../ -DBENCHMARKING=ON
```

Similarly to with the rest of this codebase, every benchmark file follows a the same structure.
In particular, every benchmark file has the extension ```.b.cpp```, and all produced executables end with ```Bench```.
For example, a benchmark for elliptic curve point addition would be called ```ECPointAdditionBench```.

Unlike with tests, we give fewer guarantees about the availability of benchmarks. This is primarily because they are harder to reason about,  and because they're less informative about how a program works to a new reader.

### Specific benchmarks

We provide two particular kinds of benchmarks that can be executed: end-to-end benchmarks and individual primitive benchmarks.
The hope is that these benchmarks should together allow one to get a full picture of how our code performs across a variety
of environments and settings.

Note that all benchmarks first require you to build the various circuits that are needed for this library to work. To do this,
first build the project and then run:

```shell
./DeriveCircuits
```

This command will output a series of Bristol Format circuits in the `build` directory as `.txt` files.
These files should all be moved into the ```../2pc/key-derivation``` directory.

#### Individual benchmarks

The individual benchmarks can be run as follows in the `build` directory.
 On one node / terminal, run the following command:

```shell
./IndividualBench --is_server --ip XXX --iterations YYY
```

where ```XXX``` is the IP address to which you wish to bind the program, and ```YYY``` is the number of times you want each
primitive to be benchmarked. This parameter is set to allow you to extract statistical results. For example, if you wanted to bind to the localhost address and to repeat each primitive five times, you would type:

```shell
./IndividualBench --is_server --ip 127.0.0.1 --iterations 5
```

Once this program launches, you can run the individual primitive benchmarks by also running the following command on another node / terminal:

```shell
./IndividualBench --ip XXX
```

For example:

```shell
./IndividualBench --ip 127.0.0.1
```

where, again, ```XXX``` is the IP address of the server machine. Note that this process does not need to specify the repetitions.
This will then print out the following information on the server's terminal:

```shell

Server: bind on ip:127.0.0.1
Starting benchmarks

ECtF P256 avg timing(ms):290.1
Bandwidth avg (mb):0.3839
...
```

Note that the client program does not output any information during the lifetime of the program. The ```IndividualBench``` program will also output the raw results of each run to an associated CSV file in the ```build``` directory.  Note, though, that this only happens on the server node.

For example, running the previous command would output a file with the following name, containing the ECtF P256 results:

```shell
ectf_p256_5.csv

# You can inspect the file using all of your favourite terminal utilities.

> cat ectf_p256_5.csv

time, bytes exchanged
303104765,402517
299933272,402517
300584422,402517
257634502,402517
289324553,402517
```

We stress that the timings may vary across runs and machines, and thus we recommend repeating the benchmarks to gain some
confidence in the results.

The circuit benchmarks output slightly more information than the individual primitive timings. In particular, we
benchmark each circuit using both the LeakyDeltaOT and Ferret OT mechanisms and record the number of bytes exchanged during each
stage of the circuit garbling process. For example, the TLS 1.3 handshake circuit with 256-bit secrets
will produce the following files:

```shell
tls13_hs_256_leaky_delta_ot_5.csv
tls13_hs_256_leaky_ferretot_5.csv

> cat tls13_hs_256_leaky_delta_ot_5.csv
setup_time, indep_time, dep_time, online_time, setup_bytes, indep_bytes, dep_bytes, online_bytes
142.8,1221.96,1661.81,153.758,25994,265960670,53875392,71680
137.753,1218.17,1661.7,157.324,25994,265960670,53875392,71680
143.124,1222.44,1650.6,155.592,25994,265960670,53875392,71680
138.763,1213.94,1659.46,159.633,25994,265960670,53875392,71680

> cat tls13_hs_256_ferret_5.csv
setup_time, indep_time, dep_time, online_time, setup_bytes, indep_bytes, dep_bytes, online_bytes
377.797,2308.32,1660.44,157.757,1920046,62987480,53875392,71680
372.138,2318.47,1664.58,155.03,1920046,62987480,53875392,71680
373.386,2319.12,1658.83,99.3341,1920046,62987480,53875392,71680
375.35,2310.2,1659,82.7837,1920046,62987480,53875392,71680
```

Again, note that the timings and amount of data exchanged may vary across machines and runs.

#### End-to-end benchmarks
The end-to-end benchmarks are intended to give a better view into how the entire DISTEFANO process runs for secret derivation. It includes each piece of the protocol that is included inside the TLS 1.3 handshake and provides detailed timings and bandwidth counts for
each piece of the protocol.

The process for running this protocol is similar to the individual benchmarks: on the server node / terminal, run the following command:

```shell
./E2EBench --is_server --ip XXX
```

As before, ```XXX``` is the IP address to which you want the program to bind. If the program is successfully
able to bind to the IP address, then it will wait for the client program to connect. For example, if we were
to run the program with an IP address of 127.0.0.1, we might see the following output:


```shell
[Server] connect to server on:127.0.0.1:51937 verifier on:127.0.0.1:36177
[Server] Running benchmark
[Server] Accepting
```

Note that the port numbers will vary between runs, but they will always be shown.

To start the benchmark proper, run the following command in another terminal / on another node:

```shell
./E2EBench --ip XXX -p PPP -v VVV
```

Here, ```XXX``` is the IP address that the server program is bound to, ```PPP``` is the port of the server program and
```VVV``` is the port of the verifier program. Using the above output as an example, we would write:

```shell
./E2EBench --ip 127.0.0.1 -p 51937 -v 36177
```

To run the program properly. As this is pretty repetitive, the server program now also outputs the string needed to
invoke the client program. Thus, the real output of the server program actually would look something like this:

```shell
[Server] connect to server on:127.0.0.1:51937 verifier on:127.0.0.1:36177
[Server] Alternatively, you can run the client program by pasting the following command into another terminal:
./E2EBench --ip 127.0.0.1 -p 51937 -v 36177
[Server] Running benchmark
[Server] Accepting
```

Once you've started the client program, you should see output that is like this on the server terminal:

```shell
[Server] Doing handshake
[Server] Finished handshake
[Server] Reading key share
[Server] Creating key share
[Server] Preprocessing circuits
...
```

At the end of the run, this will also include various timings and bandwidth results.


## Generating documentation
As with tests, we like documentation. Whilst each file is documented individually,
you can generate project-wide documentation by running:

```
doxygen
```

This will produce a series of HTML pages containing the documentation for this project.
You can find this documentation in the ```html``` directory. To view it all,
open ```html/index.html``` in a browser.

Each function is documented with a description of what the
function does. We also list necessary pre-conditions for calling the
function in contract, and a description of all parameters. In addition,
each function contains its test case in the documentation: we recommend reading the
test cases if you wish to understand the behaviour of the functions.

## Quirks / known pain points
Any project of sufficiently large size will have quirks or pain points. We list known ones here:

- We use ```uint8_t``` to represent a byte. This is primarily to match existing BoringSSL code.
  This isn't optimal from either a semantic or performance perspective. On the semantic side,
  it would be nicer to use C++17's ```std::byte```. From a performance perspective, it would
  be nice to use C++20's ```char8_t```, as operations over this type can be vectorised due to a
  change in type aliasing rules.

- At the moment this library does not support Curve25519 for any arithmetic.

- We use a nasty hack to test parts of this library. In particular, we install a hook [here](https://github.com/brave-experiments/DECO-and-TLS-1.3/blob/9b1f90f552a708d748639029bb13f00183174030/src/boringssl/ssl/internal.h#L3763) into ```SSL``` contexts that are under test. The point of these hooks is to
throw an exception when a certain point in the handshake is reached, which we then catch from test code. The reason for this is because the BoringSSL handshake continues until it has finished. However,
for our purposes this isn't always great, especially if we just want to test a portion of the handshake code. Because C++ exceptions automatically propagate, throwing an exception like this will unwind
the program stack nicely until we catch the exception in our test code.
This may go away at some point.

- We use a C++ idiom called the "immediately invoked lambda expression" at times in this project.
  Have you ever wanted to be able to write this:

  ```c++
  const uint16_t var;
  FUNC_THAT_OVERWRITES_VAR(&var);
  // var is constant after this point?
  ```

  Yeah, us too. The immediately invoked lambda expression lets you write something similar:
  ```c++
  const uint16_t var = [&]() {
      uint16_t var2;
      FUNC_THAT_OVERWRITES_VAR(&var2);
      return var2;
  }(); // Note the () : it means the lambda is invoked immediately!
  ```

  This can be really useful in some situations.

- At various points in time the tests running in this library may be marked as leaking memory. This
  is primarily because we sometimes recklessly pause the TLS handshake to make sure that
  we have the "right" output at each stage. This is a bit of a pain, but it's possibly unavoidable
  right now.

## Changes introduced

- Set and get functions for key share structure (only for the client) with tests
- Added a set_verifier functionality (only for the client) to set the verifier structure with tests
- Added a ThreePartyHandshake namespace which accepts an SSL object (representing a current SSL connection) and (using that SSL's object |verifier|) contacts a third party in order to generate shared keyshares. Concretely, this function forwards the SSL object's |hs| values to another party, who then replies with a new set of |hs| values for the SSL object to use in the outgoing handshake. It implements unpacking and packing functionality with tests.
- Added `key_store` field to the `ssl_st` structure to store our share of the three-party handshake keys, so we keep the state of the original key_shares.
- Create utility functions for: extracting nid (`get_nid_from_uint16`), `CBBToECPoint`,
- Change internal.h, ssl/ssl_key_share.cc,  file (https://github.com/brave-experiments/tls-attestation/commit/29be2fb3f416a697c9c13c6c99980770edcccbe6) to return the ‘y’ coordinate of curves.
- Add sockets: https://github.com/brave-experiments/tls-attestation/commit/a7310e6df3e3d737f2a7d6cd3f8601756ea2d914
- Tests for the 3PH: https://github.com/brave-experiments/tls-attestation/commit/e6891866ca24ec32ff8265941fd2b5af541dd4ba

# Other resources used
* For MPC: EMP, Efficient Multi-Party computation toolkit: https://github.com/emp-toolkit
* MTA: https://eprint.iacr.org/2021/1373

## Understanding the code
There's a fair bit of code that has been produced in the course of this project: at the time
of writing, there's over 10,000 lines of documentation, tests, and code (not including external libraries). This means that
looking at the code for the first time can be a bit daunting: this section is meant to help
with establishing this understanding.

### Directory layout
This directory has the following directories:

1. ```2pc```. This directory contains all of the code for generating circuits to be used inside e.g Garbled circuits.
2. ```boringssl```. This directory contains a tweaked version of BoringSSL.
3. ``` emp-ag2pc```. This directory contains a tweaked version of the authenticated garbling library that comes as part of emp.
4. ```emp-ot```. This directory contains a tweaked version of the ```emp-ot``` library.
5. ```emp-tool```. This directory contains a tweaked version of the ```emp-tool``` library.
6. ```mta```. This directory contains an implementation of the multiplicative-to-additive (mta) protocol we use, alongside the elliptic-curve-to-field (ectf) implementation.
7. ```nodes```. This directory contains an implementation of a basic server. This basic
    server can be thought of as the verifier in the protocol.
8. ```ssl```. This directory contains an implementation of various utilities for interacting with
BoringSSL. This includes some socket wrappers, as well as the code for the three party handshake.

The code itself is heavily documented and tested. As a result, it should be fairly easy to find what you're looking for by looking at the requisite files in these directories.

### Coding style
The coding style used in this code base is a little bit inconsistent.

The primary reason for this is because the BoringSSL library uses an idiomatic C coding style, rather than an idiomatic C++ coding style. As a result, for good compatibility with BoringSSL, we follow a C-style coding convention where necessary.

In particular, this has the implication of making the functions that interact with BoringSSL look a certain way.  Most functions that interact with BoringSSL directly accept parameters via input pointers and return results via output pointers. The return channel is typically reserved exclusively for a status code. For example, the three party handshake code features functions that look like this:

```c
bool three_party_handshake_send_received_key_shares(SSL * ssl, uint16_t, CBS& cbs);
```

Whereas a more idiomatic C++ function would not take the ```SSL``` argument as a
pointer if it cannot be null (we would instead take a reference, similarly to the ```cbs``` parameter).  For similar reasons, the code in this library does not use any C++ exceptions: since C
doesn't understand exceptions, it is unlikely that the BoringSSL code could deal with these errors properly.

However, for code that is unlikely to interact directly with the BoringSSL library we use more
idiomatic C++.

This does mean that there's a small amount of disuniformity across the code base. This
could be fixed, but it seems like this is the right trade-off without modifying BoringSSL too
intensely.

### How does our code interact with BoringSSL?

The version of BoringSSL that is in this directory has been modified in a few ways. Without
listing them all here, we wish to highlight how these modifications are useful and
how they enable further extensibility without modifying BoringSSL too extensively.

#### Function pointers: a primer
For the sake of understanding, we briefly describe the concept of a _function pointer_.
Recall that a pointer is a variable that contains the address of some memory location as its value. In C, pointers are denoted with an asterisk, as shown below.

```C
// x is a pointer to an integer.
int *x;
// y is a pointer to a double.
double *y;
// Pointers are the same size, regardless of what they point to. This is because
// the machine addresses are all the same size.
struct ReallyLargeObject{...};

struct ReallyLargeObject * rlo;
_Static_assert(sizeof(rlo) == sizeof(y), "This cannot happen.");
```

You have probably encountered pointers like these before: they're ubiquitous in systems programming. However, a less common (but still not obscure) concept is
a _function pointer_. Intuitively, a function pointer is a variable that contains the address of a function as its value. For example:

```C
// Try for yourself: https://godbolt.org/z/qW1b8YWac
int f(); // The function
int(*FunctionPointer)() = &f; // The pointer to the function.
```

The syntax for function pointers is notoriously difficult to get right. This is because of how
the C language grammar is specified. Nevertheless, the following guide rules are typical:

1. The return type goes first. For example, if the function `f` above instead returned a `double`, we would write `double(*FunctionPointer)() = &f;` instead.
2. The parameters go in the second set of parentheses. For example, if `f` took an `int` as
    an argument, we would write `int(*FunctionPointer)(int) = &f;` instead.
3. Finally, the name of the function pointer goes next to the `*`.


Function pointers have a wide range of uses. Here, we shall focus just on two aspects: the ability to call out to arbitrary code, and the ability to pass the pointers around.

For example, consider the following code. The files where each function live are
given in the comments.

```C
// Try for yourself: https://godbolt.org/z/eqnshhWWr
// Note that the code above is all in one file: this seems necessary there.

// Adder.h
struct Adder {
    // This is a function pointer to a function that accepts a single int
    // and returns an int.
    int(*op)(int);
};

// This is a free function that returns an Adder that adds "5" to any input.
struct Adder * make_five_adder();

// Adder.c

// Note that this is a static function: in C, this means that the function is file-local.
// In other words, add_five cannot be called by name outside of Adder.c
#include<stdlib.h>
static int add_five(int val) {
    return val + 5;
}

struct Adder * make_five_adder() {
    struct Adder* adder = malloc(sizeof(*adder));
    adder->op = add_five;
    return adder;
}

// main.c
#include<cstdlib.h>
#include<stdio.h>
#include "Adder.h"

void long_running_computation(struct Adder * adder) {
    // Imagine some long running computation
    int val = rand() % 4096;
    int plus_something = adder->op(val);
    printf("%d,%d", val, plus_something);
}

int main(int argc, char* argv[]) {
    struct Adder * adder = make_five_adder();
    long_running_computation(adder);
    free(adder);
    return 0;
}
```

If we assume that the above code generates a random value of ```13``` in ```long_running_computation```, then as output we will see ```13, 18```.
Notice, however, that the ```long_running_computation``` code doesn't know anything about the exact function that is called here: it simply calls ```adder->op``` directly, regardless
of what it points to. In some situations, this can be dangerous: for example, if ```adder->op``` were a null pointer, then the program would crash.
However, if we are careful, then this technique permits us to implement some clever tricks.

#### Why are these useful for us?
Now that we understand what function pointers are, we can begin to see how they are useful for us.

Firstly, notice that function pointers can be null. This means that it's very possible for us to write code like this:
```C
// Assume f is a function pointer
if(f && f(...)) {
    ...
}
```

The implication of this is that we can conditionally execute certain code in certain parts of the program. This is a rather common way to implement callbacks.

The second usage of this is that we can store these function pointers. This means that we can execute code depending on the particular object we're
using. We already saw this above, but concretely, this looks something like this:

```C
struct Adder {
    int(*op)(int);
};

int add_3(int val) {
    return val + 3;
}

int add_5(int val) {
    return val + 5;
}

int main(void) {
    struct Adder add_3, add_5;
    add_3.op = add_3;
    add_5.op = add_5;

    int value = rand() % 4096;
    return add_3.op(add_5.op(value));
}
```

The key idea here is that different instances of ```Adder``` can be used for this sort of addition.

Finally, notice that we can actually change (at runtime) the code that a particular function pointer calls. We've already done this above by setting the
```op``` member to a pointer.

The takeaway of all of these things, therefore, is as follows:

1. If we want to conditionally call out of BoringSSL to third-party code, we can use function pointers.
2. Each SSL object (e.g an SSL*) can have a pointer to a different piece of code for each outcome.
3. If any particular pointer is null, then BoringSSL can continue as before.
4. Otherwise, we can call out to some code that lives (potentially) outside of BoringSSL.

This means that we can add a wide variety of functionality to BoringSSL without modifying BoringSSL itself extensively.  The code doesn't even need to be a part
of BoringSSL directly: for example, if we provide this API:

```C
void set_callback(SSL * ssl, ...); // Here the ... is a function pointer type of some kind.
```

Then from anywhere else in the program we can call:

```C
set_callback(ssl, f);
```

Notice that the base library doesn't need to know anything a priori about `f`: the caller simply passes `f` in directly.  This means that we can minimise the amount of disruption
to BoringSSL.

#### FFI
One last thing: it turns out that using function pointers in this way can allow us to call out of C into other languages, such as Rust. Provided the provided function respects a rather
basic calling convention, it is possible to supply arbitrary functions here to use as a function pointer. This means that, amongst other things, we can use a higher-level language
for writing our code, or take advantage of other advanced features (such as closures or generics).

# References
- [HMRT22] Iftach Haitner, Nikolaos Makriyannis, Samuel Ranellucci, and Eliad Tsfadia, Highly Efficient OT-Based Multiplication Protocols, Eurocrypt 2022, https://eprint.iacr.org/2021/1373
- [Lakos20] John Lakos, Large-Scale C++ Volume I: Process and Architecture, Addison-Wesley Professional Computing Series, 2020, https://www.pearson.com/uk/educators/higher-education-educators/program/Lakos-Large-Scale-C-Volume-I-Process-and-Architecture/PGM483708.html
