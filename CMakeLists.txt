cmake_minimum_required(VERSION 3.13)

PROJECT(netifd C)

include(CheckCCompilerFlag)
check_c_compiler_flag(-Wimplicit-fallthrough HAS_IMPLICIT_FALLTHROUGH)

ADD_DEFINITIONS(-Wall -Werror)
IF(CMAKE_C_COMPILER_VERSION VERSION_GREATER 6)
	add_definitions(-Wextra -Werror=implicit-function-declaration)
	add_definitions(-Wformat -Werror=format-security -Werror=format-nonliteral)
ENDIF()
ADD_DEFINITIONS(-Os --std=gnu99 -Wmissing-declarations -Wno-unused-parameter -Wno-unused-but-set-parameter)

IF(HAS_IMPLICIT_FALLTHROUGH)
  ADD_DEFINITIONS(-Wimplicit-fallthrough)
ENDIF()

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES
	main.c utils.c system.c tunnel.c handler.c
	interface.c interface-ip.c interface-event.c
	iprule.c proto.c proto-static.c proto-shell.c
	config.c device.c bridge.c veth.c vlan.c alias.c
	macvlan.c ubus.c vlandev.c extdev.c bonding.c
	ucode.c)


FIND_LIBRARY(uci NAMES uci)
FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(ucode NAMES ucode)
FIND_LIBRARY(json NAMES json-c json)
FIND_LIBRARY(udebug NAMES udebug)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)

SET(LIBS ${ubox} ${ubus} ${uci} ${json} ${blobmsg_json} ${udebug} ${ucode})

FIND_PATH(ubox_include_dir libubox/usock.h)
FIND_PATH(ucode_include_dir ucode/vm.h)
FIND_PATH(udebug_include_dir udebug.h)
INCLUDE_DIRECTORIES(${ubox_include_dir} ${ucode_include_dir})

IF (NOT DEFINED LIBNL_LIBS)
	include(FindPkgConfig)
	pkg_search_module(LIBNL libnl-3.0 libnl-3 libnl nl-3 nl)
	IF (LIBNL_FOUND)
		include_directories(${LIBNL_INCLUDE_DIRS})
		SET(LIBNL_LIBS ${LIBNL_LIBRARIES})
	ENDIF()
ENDIF()

ADD_CUSTOM_COMMAND(
	OUTPUT ethtool-modes.h
	COMMAND ./make_ethtool_modes_h.sh ${CMAKE_C_COMPILER} > ./ethtool-modes.h
	DEPENDS ./make_ethtool_modes_h.sh
)
ADD_CUSTOM_TARGET(ethtool-modes-h DEPENDS ethtool-modes.h)

IF("${CMAKE_SYSTEM_NAME}" MATCHES "Linux" AND NOT DUMMY_MODE)
	SET(SOURCES ${SOURCES} system-linux.c)
	SET(LIBS ${LIBS} ${LIBNL_LIBS})
ELSE()
	ADD_DEFINITIONS(-DDUMMY_MODE=1)
	SET(SOURCES ${SOURCES} system-dummy.c)
ENDIF()

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
  IF(NO_OPTIMIZE)
    ADD_DEFINITIONS(-O0)
  ENDIF()
ENDIF()


ADD_EXECUTABLE(netifd ${SOURCES})

TARGET_LINK_LIBRARIES(netifd ${LIBS})

INSTALL(TARGETS netifd
	RUNTIME DESTINATION sbin
)
ADD_DEPENDENCIES(netifd ethtool-modes-h)
