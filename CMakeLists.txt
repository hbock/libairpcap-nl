cmake_minimum_required (VERSION 2.6)

project (airpcap-nl)

set (airpcap_VERSION_MAJOR 4)
set (airpcap_VERSION_MINOR 1)
set (airpcap_VERSION_REV   1)
set (airpcap_VERSION_BUILD 1)

include_directories ("${PROJECT_BINARY_DIR}")
add_definitions (-std=c99 -Wall -Wextra -g -O0 -D_GNU_SOURCE)
find_library (NL_LIBRARY nl)
find_library (NL_GENL_LIBRARY nl-genl)

# libnl-genl is merged with libnl for version 1, so use
# this to detect which nl we have.
if (NL_GENL_LIBRARY)
  message("libnl 2 found, linking against -lnl -lnl-genl")
  set (SOLIBS ${SOLIBS} nl nl-genl)
  set (CONFIG_LIBNL20 TRUE)
else (NL_GENL_LIBRARY)
  message("libnl 1 found, linking against -lnl")
  set (SOLIBS ${SOLIBS} nl)
  set (CONFIG_LIBNL20 FALSE)
endif (NL_GENL_LIBRARY)

# Generate this after determining libnl version
configure_file (
  "${PROJECT_SOURCE_DIR}/airpcap-nl-config.h.in"
  "${PROJECT_BINARY_DIR}/airpcap-nl-config.h"
)

set (airpcap_nl_source airpcap-nl.c stubs.c util.c)

add_library (airpcap-nl SHARED ${airpcap_nl_source})
set_target_properties (airpcap-nl PROPERTIES VERSION ${airpcap_VERSION_MAJOR}.${airpcap_VERSION_MINOR}
                                             SOVERSION ${airpcap_VERSION_MAJOR})
target_link_libraries (airpcap-nl ${SOLIBS})

add_executable (driver driver.c)
target_link_libraries (driver airpcap-nl pcap)

install (
  TARGETS airpcap-nl
  LIBRARY DESTINATION lib
)
