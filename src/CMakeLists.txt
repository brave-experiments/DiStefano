cmake_minimum_required(VERSION 3.5)
project(TLSAttestation VERSION 0.1)

# ##############################################################################
# General flags
# ##############################################################################

# We use C++17 in this project because: 1) It's what Chromium supports (see
# https://chromium.googlesource.com/chromium/src/+/HEAD/styleguide/c++/c++.md
# "Modern C++ features") 2) C++17 drastically improved template support in the
# language. Although the code in this codebase is very much "C with classes,
# plus auto" we use templates in one place and it makes life much better.
#
# If this is a deal breaker then we can drop down to C++11.
set(CMAKE_CXX_STANDARD 17)

# This produces a json file that let's you jump into various file definitions
# etc This can be useful if you use VSCode, but it's also useful if you have an
# editor that supports clangd more generally.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


# Allow conditional benchmarking. You can set this by running CMake with
# -DBENCHMARKING=ON.
option(BENCHMARKING "Build benchmarks" OFF)

if(NOT ${BENCHMARKING})
  message("Benchmarking not set")
else()
  message("Benchmarking set")
endif()

# ##############################################################################
# BoringSSL
# ##############################################################################
add_subdirectory(boringssl)

# SYSTEM here means that the include paths are mapped from "" to <>. This is so
# we can include nested header files in our code.
# Note that this version of BoringSSL is slightly tweaked: we remove some diagnostic flags
# from their CMakeLists to make sure that Clang doesn't complain.
include_directories(SYSTEM "boringssl/include" "boringssl")
enable_testing()

# ##############################################################################
# EmpTool
# ##############################################################################

# N.B Emptool must be configured to use SHA2 instead of SHA-3. This is primarily
# for compatibility with BoringSSL. We use a explicitly modified version for this
# task.
include_directories(SYSTEM "emp-tool" "emp-ot" "emp-ag2pc")
add_subdirectory("emp-tool")

# N.B EmpTool needs a directory to store the pre OT secrets. No idea why -- maybe
# for resumability? Anyway, this makes one in the build directory
file(MAKE_DIRECTORY "build/data")

# ##############################################################################
# WARNINGS
# ##############################################################################

# Feel free to add to these. Note that GCC and Clang each support different
# flags, so we'll only add extra flags if GCC (the GNU compiler) is detected.
set(WARNINGS
    -Wall
    #-Werror
    -Wextra
    -Wshadow
    -Wpedantic
    -Wextra-semi
    -Wredundant-decls
    -Wctor-dtor-privacy
    -Wfloat-equal
    -Wformat-security
    -Wnon-virtual-dtor
    -Wunused
    # These are omitted just so that we can continue piecewise developing.
    -Wno-error=unused-parameter    
    -Wno-error=return-type
    -Woverloaded-virtual
    -Wsign-conversion
    -Wconversion
    -Wmisleading-indentation
    -Wnull-dereference
    -Wshift-overflow
    -Wstrict-overflow=2
    -Wdouble-promotion
    -Wformat=2
    -Wcast-qual
    -Wmissing-declarations
    -Wsign-promo)


if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  list(
    APPEND
    WARNINGS
    -Wstrict-null-sentinel
    -Wformat-signedness
    -Wformat-overflow
    -Wduplicated-branches
    -Wlogical-op
    -Wuseless-cast)
endif()

# LIB_ASAN is a memory bounds checker. It should come with your C++ compiler,
# but if it doesn't exist then you can comment this out.

# Note: this if block is to handle the (seemingly common situation) of compiling
# on an M1 Mac: there, ASAN isn't supported it seems. Note that the ordering matters
# here, as UNIX is set on Macos.
if(APPLE)
  set(LIB_ASAN)
elseif(UNIX)
  # GCC doesn't support memory sanitizer, only clang.
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(LIB_ASAN -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize=vptr)
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(LIB_ASAN -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize=vptr)
  endif()
else()
  set(LIB_ASAN)
endif()

# Note that the debug flags also adds debug info for standard library calls:
# this is primarily to make sure that we aren't violating any standard library assumptions.
# This comes at a pretty big performance cost though.

set(G_C_DEBUG_FLAGS "-ggdb -fno-omit-frame-pointer -fstack-protector-all" "${WARNINGS}")
set(G_C_DEBUG_ASAN_FLAGS "-ggdb -D_GLIBCXX_DEBUG -fno-omit-frame-pointer -fstack-protector-all" "${LIB_ASAN}" "${WARNINGS}")
set(G_C_OPT_FLAGS "-ggdb -fno-omit-frame-pointer -Ofast -DNDEBUG" "${WARNINGS}")

# Clang doesn't support -mno-avx512f
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  list(APPEND G_C_DEBUG_FLAGS -mno-avx512f)
  list(APPEND G_C_OPT_FLAGS -mno-avx512f)
endif()

# Same problem as above, but with optimisation flags.
# These are primarily needed for e.g inlining forcibly inlined functions
# such as machine intrinsics. Note that AppleClang needs to be handled separately
# because it doesn't support march=native, so we just assume you're using an M1
# and hope for the best.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  list(APPEND G_C_OPT_FLAGS
    -march=native)
  list(APPEND G_C_DEBUG_FLAGS
    -march=native)
  list(APPEND G_C_DEBUG_ASAN_FLAGS
    -march=native)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
  list(APPEND G_C_OPT_FLAGS
    -mcpu=apple-m1)
  list(APPEND G_C_DEBUG_FLAGS
    -mcpu=apple-m1)
    list(APPEND G_C_DEBUG_ASAN_FLAGS
      -mcpu=apple-m1)
endif()

set(G_L_FLAGS "ssl" "emp-tool")
set(G_LA_FLAGS "ssl" "emp-tool" "${LIB_ASAN}")
# We don't link against asan in benchmark mode.
set(B_L_FLAGS "ssl" "emp-tool")

# This splits up the arguments into a form that CMAKE can deal with when passing
# to executables
separate_arguments(C_DEBUG_FLAGS UNIX_COMMAND "${G_C_DEBUG_FLAGS}")
separate_arguments(C_DEBUG_ASAN_FLAGS UNIX_COMMAND "${G_C_DEBUG_ASAN_FLAGS}")
separate_arguments(C_OPT_FLAGS UNIX_COMMAND "${G_C_OPT_FLAGS}")
separate_arguments(CDU_FLAGS UNIX_COMMAND "${G_C_DEBUG_FLAGS_UBSAN}")
separate_arguments(L_FLAGS UNIX_COMMAND "${G_L_FLAGS}")
separate_arguments(L_ASAN_FLAGS UNIX_COMMAND "${G_LA_FLAGS}")
separate_arguments(B_FLAGS UNIX_COMMAND "${B_L_FLAGS}")
separate_arguments(UL_FLAGS UNIX_COMMAND "${G_L_U_FLAGS}")

# Put all the source files in one place.
set(SRC_FILES
  ssl/ThreePartyHandshake.cpp
  ssl/Util.cpp
  ssl/StatefulSocket.cpp
  ssl/TLSSocket.cpp
  ssl/Messaging.cpp
  ssl/EmpWrapper.cpp
  ssl/EmpWrapperAG2PC.cpp
  ssl/SSLBuffer.cpp
  ssl/CounterType.cpp
  ssl/NoBuffer.cpp
  nodes/Server.cpp
  nodes/KeyShare.cpp
  mta/MtA.cpp
  mta/F2128MtA.cpp
  mta/EmpBlockSpan.cpp
  mta/EmpBlockArray.cpp
  mta/ectf.cpp
  mta/PackArray.cpp
  mta/SenderEntry.cpp
  mta/ReceiverEntry.cpp
  2pc/CircuitSynthesis.cpp)

# Create libraries to make compilation of tests faster
add_library(TLSAttestDebug STATIC "${SRC_FILES}")
add_library(TLSAttestDebugAsan STATIC "${SRC_FILES}")
add_library(TLSAttestOpt STATIC "${SRC_FILES}")

# We'll also build doctest as a static library once too NB Doctest doesn't need
# to be linked against anything else.
add_library(Doctest STATIC doctest.cpp)
target_compile_options(Doctest PRIVATE ${C_DEBUG_FLAGS})

# Link the TLSAttest libraries against ssl and (optionally) libasan.
target_compile_options(TLSAttestDebug PRIVATE ${C_DEBUG_FLAGS})
target_link_libraries(TLSAttestDebug PRIVATE ${L_FLAGS})
target_compile_options(TLSAttestDebugAsan PRIVATE ${C_DEBUG_ASAN_FLAGS})
target_link_libraries(TLSAttestDebugAsan PRIVATE ${L_ASAN_FLAGS})
target_compile_options(TLSAttestOpt PRIVATE ${C_OPT_FLAGS})
target_link_libraries(TLSAttestOpt PRIVATE ${L_FLAGS})

set(SSLTARGETS Util EmpWrapper EmpWrapperAG2PC ThreePartyHandshake StatefulSocket TLSSocket Messaging SSL SSLBuffer NoBuffer CounterType)
set(NodeTARGETS Server KeyShare)
set(MTATARGETS MtA F2128MtA EmpBlockOwningSpan EmpBlockNonOwningSpan EmpBlockArray ectf PackArray)
set(2PCTARGETS CircuitSynthesis)

# We'll produce a different test executable for each test file. This is to make
# it easier to test in parallel.
# Also, to avoid repeating and re-repeating this, we use a function that does the same thing
# repeatedly.
function(make_tests TARGETS FILEPATH)
  foreach(TARGET ${TARGETS})
    add_executable(${TARGET}DebugTests ${FILEPATH}/${TARGET}.t.cpp)
    add_executable(${TARGET}DebugAsanTests ${FILEPATH}/${TARGET}.t.cpp)
    add_executable(${TARGET}OptTests ${FILEPATH}/${TARGET}.t.cpp)

    target_compile_options(${TARGET}DebugTests PRIVATE ${C_DEBUG_FLAGS})
    target_compile_options(${TARGET}DebugAsanTests PRIVATE ${C_DEBUG_ASAN_FLAGS})
    target_compile_options(${TARGET}OptTests PRIVATE ${C_OPT_FLAGS})

    target_link_libraries(${TARGET}DebugTests PRIVATE TLSAttestDebug Doctest
      ${L_FLAGS})
    target_link_libraries(${TARGET}OptTests PRIVATE TLSAttestOpt Doctest
      ${L_FLAGS})
     target_link_libraries(${TARGET}DebugAsanTests PRIVATE TLSAttestDebugAsan Doctest
      ${L_ASAN_FLAGS})

    add_test(${TARGET}DebugTests ${TARGET}DebugTests)
    add_test(${TARGET}DebugAsanTests ${TARGET}DebugAsanTests)
    add_test(${TARGET}OptTests ${TARGET}OptTests)
  endforeach(TARGET)
endfunction()

make_tests("${SSLTARGETS}" "ssl")
make_tests("${NodeTARGETS}" "nodes")
make_tests("${MTATARGETS}" "mta")
make_tests("${2PCTARGETS}" "2pc")

# This file builds the circuits that are needed for 2PC work.
add_executable(DeriveCircuits 2pc/DeriveCircuits.cpp)
target_compile_options(DeriveCircuits PRIVATE ${C_DEBUG_FLAGS})
target_link_libraries(DeriveCircuits PRIVATE TLSAttestDebug ${L_FLAGS})

# ##############################################################################
# Benchmarking
# ##############################################################################

# This section contains the definitions etc for micro benchmarks.
if(BENCHMARKING)
  message("Benchmark set")
  # Alas, C+++ pales in comparison to modern langauges that ship with benchmarking
  # support by default. We use Google benchmark to get around this.

  # WARNING: these definitions here are to stop benchmark also needing Google
  # Test. We don't want to test Google Benchmark after all.
  set(CMAKE_BUILD_TYPE Release)
  set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
  set(BENCHMARK_ENABLE_TESTING OFF)
  add_subdirectory(benchmark)


  # We build a faster version of the library, with less bloat.
  add_library(TLSAttestBench STATIC "${SRC_FILES}")
  target_compile_options(TLSAttestBench PRIVATE ${C_OPT_FLAGS})
  target_link_libraries(TLSAttestBench PRIVATE ${L_FLAGS})

  set(BENCHMARKS ECPointAdd MtA F2128MtAClient F2128MtAServer ECtFServer ECtFClient)

  # And link each executable sepearately.
  foreach(BENCH ${BENCHMARKS})
    add_executable(${BENCH}Bench benchmarks/${BENCH}.b.cpp)
    target_compile_options(${BENCH}Bench PRIVATE ${C_OPT_FLAGS})
    target_link_libraries(${BENCH}Bench PRIVATE TLSAttestBench ${L_FLAGS} "benchmark::benchmark" "benchmark::benchmark_main")
  endforeach(BENCH)

  # Link the individual and E2E benchmarks separately.
  add_executable(IndividualBench benchmarks/IndividualBench.b.cpp)
  target_compile_options(IndividualBench PRIVATE ${C_OPT_FLAGS})
  target_link_Libraries(IndividualBench PRIVATE TLSAttestBench ${L_FLAGS})

  add_executable(E2EBench benchmarks/E2E.b.cpp)
  target_compile_options(E2EBench PRIVATE ${C_OPT_FLAGS})
  target_link_Libraries(E2EBench PRIVATE TLSAttestBench ${L_FLAGS})
endif()


