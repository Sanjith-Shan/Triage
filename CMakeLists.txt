cmake_minimum_required(VERSION 3.20)
project(Triage LANGUAGES C CXX)

# Triage — fuzzing and exploitability-triage instrument.
#
# Two fuzzing engines share one target contract (include/triage/fuzzer.h):
#   * libfuzzer  — coverage-guided, real campaigns (Linux, or any clang shipping
#                  the libFuzzer runtime). Provides main(); uses the target's
#                  LLVMFuzzerCustomMutator automatically.
#   * standalone — a corpus-replay / fork-mutate runner for hosts without the
#                  libFuzzer runtime (Apple clang). Links targets/standalone_main.c.
#
# TRIAGE_ENGINE=auto picks libfuzzer when the runtime links, else standalone.

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(TRIAGE_ENGINE "auto" CACHE STRING "fuzzing engine: auto|libfuzzer|standalone")
set(TRIAGE_SANITIZE "address,undefined" CACHE STRING "sanitizers for target builds")
option(TRIAGE_TARGET_LIBCOAP  "build the libcoap CoAP fuzz target"       OFF)
option(TRIAGE_TARGET_CBOR     "build the tinycbor fuzz target"          OFF)
option(TRIAGE_TARGET_FREETYPE "build the FreeType seeded-rediscovery"    OFF)

# ---- engine detection --------------------------------------------------------
set(_have_libfuzzer FALSE)
if(TRIAGE_ENGINE STREQUAL "libfuzzer")
  set(_have_libfuzzer TRUE)
elseif(TRIAGE_ENGINE STREQUAL "auto")
  set(_probe "${CMAKE_BINARY_DIR}/lf_probe.c")
  file(WRITE "${_probe}"
       "#include <stdint.h>\n#include <stddef.h>\n"
       "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){return 0;}\n")
  try_compile(_have_libfuzzer "${CMAKE_BINARY_DIR}/lf_try" "${_probe}"
              COMPILE_DEFINITIONS "-fsanitize=fuzzer"
              LINK_OPTIONS "-fsanitize=fuzzer")
endif()

if(_have_libfuzzer AND NOT TRIAGE_ENGINE STREQUAL "standalone")
  set(_engine "libfuzzer")
else()
  set(_engine "standalone")
endif()
message(STATUS "Triage engine: ${_engine} (sanitizers: ${TRIAGE_SANITIZE})")

separate_arguments(_san UNIX_COMMAND "-fsanitize=${TRIAGE_SANITIZE}")

# Instrument the WHOLE build — including libraries pulled in via FetchContent —
# so libFuzzer gets coverage feedback from inside the target library, not just
# the driver. Without this the external targets fuzz blind (coverage stays ~2)
# and never reach deep code. `fuzzer-no-link` adds SanitizerCoverage to every TU
# but leaves main() to the fuzz-target link step. This is the OSS-Fuzz pattern.
add_compile_options(-g -O1 ${_san})
if(_engine STREQUAL "libfuzzer")
  add_compile_options(-fsanitize=fuzzer-no-link)
endif()

# triage_add_target(NAME SOURCES <files...>)
# Builds a fuzz target executable under the selected engine + sanitizers. Compile
# instrumentation comes from the global options above; this only settles main()
# and the link.
function(triage_add_target NAME)
  cmake_parse_arguments(A "" "" "SOURCES" ${ARGN})
  add_executable(${NAME} ${A_SOURCES})
  target_include_directories(${NAME} PRIVATE "${CMAKE_SOURCE_DIR}/include")
  if(_engine STREQUAL "libfuzzer")
    target_link_options(${NAME} PRIVATE -fsanitize=fuzzer ${_san})
  else()
    target_sources(${NAME} PRIVATE "${CMAKE_SOURCE_DIR}/targets/standalone_main.c")
    target_link_options(${NAME} PRIVATE ${_san})
  endif()
endfunction()

# ---- in-repo targets ---------------------------------------------------------
triage_add_target(mferf_fuzz SOURCES
  "${CMAKE_SOURCE_DIR}/targets/mferf/mferf.c"
  "${CMAKE_SOURCE_DIR}/targets/mferf/driver.c")
target_include_directories(mferf_fuzz PRIVATE "${CMAKE_SOURCE_DIR}/targets/mferf")

# patched build, for regression comparison
triage_add_target(mferf_fuzz_patched SOURCES
  "${CMAKE_SOURCE_DIR}/targets/mferf/mferf.c"
  "${CMAKE_SOURCE_DIR}/targets/mferf/driver.c")
target_include_directories(mferf_fuzz_patched PRIVATE "${CMAKE_SOURCE_DIR}/targets/mferf")
target_compile_definitions(mferf_fuzz_patched PRIVATE MFERF_PATCHED)

# HTTP differential target (two in-repo parsers + divergence oracle)
if(EXISTS "${CMAKE_SOURCE_DIR}/targets/http_diff/diff_driver.c")
  triage_add_target(http_diff_fuzz SOURCES
    "${CMAKE_SOURCE_DIR}/targets/http_diff/parser_a.c"
    "${CMAKE_SOURCE_DIR}/targets/http_diff/parser_b.c"
    "${CMAKE_SOURCE_DIR}/targets/http_diff/diff_driver.c")
  target_include_directories(http_diff_fuzz PRIVATE "${CMAKE_SOURCE_DIR}/targets/http_diff")
endif()

# ---- external real targets (opt-in, fetched) ---------------------------------
include(FetchContent)

if(TRIAGE_TARGET_LIBCOAP)
  FetchContent_Declare(libcoap
    GIT_REPOSITORY https://github.com/obgm/libcoap.git
    GIT_TAG v4.3.5)  # confirm/adjust; a recent release with the 2024-25 CVE window
  set(ENABLE_DTLS OFF CACHE BOOL "" FORCE)
  set(ENABLE_TESTS OFF CACHE BOOL "" FORCE)
  set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(libcoap)
  triage_add_target(coap_fuzz SOURCES "${CMAKE_SOURCE_DIR}/targets/external/coap_fuzz.c")
  target_link_libraries(coap_fuzz PRIVATE coap-3)
endif()

if(TRIAGE_TARGET_CBOR)
  FetchContent_Declare(tinycbor
    GIT_REPOSITORY https://github.com/intel/tinycbor.git
    GIT_TAG main)  # tinycbor has no CMake; see docs/EXTERNAL_TARGETS.md for the
                   # object-build note. Pin a commit before campaigning.
  FetchContent_MakeAvailable(tinycbor)
  triage_add_target(cbor_fuzz SOURCES "${CMAKE_SOURCE_DIR}/targets/external/cbor_fuzz.c")
  target_include_directories(cbor_fuzz PRIVATE "${tinycbor_SOURCE_DIR}/src")
  # link the tinycbor objects; see docs/EXTERNAL_TARGETS.md
endif()

if(TRIAGE_TARGET_FREETYPE)
  FetchContent_Declare(freetype
    GIT_REPOSITORY https://gitlab.freedesktop.org/freetype/freetype.git
    GIT_TAG VER-2-13-0)  # pre-fix for CVE-2025-27363 (fixed in 2.13.3)
  FetchContent_MakeAvailable(freetype)
  triage_add_target(freetype_fuzz SOURCES "${CMAKE_SOURCE_DIR}/targets/external/freetype_fuzz.c")
  target_link_libraries(freetype_fuzz PRIVATE freetype)
endif()

# ---- tests -------------------------------------------------------------------
enable_testing()
find_program(PYTEST NAMES pytest)
if(PYTEST)
  add_test(NAME pytest COMMAND ${PYTEST} -q "${CMAKE_SOURCE_DIR}/tests")
  set_tests_properties(pytest PROPERTIES WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
endif()
