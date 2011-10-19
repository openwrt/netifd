cmake_minimum_required(VERSION 2.6)

PROJECT(netifd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

SET(SOURCES
	main.c utils.c
	interface.c interface-ip.c interface-event.c
	proto.c proto-static.c proto-shell.c
	config.c device.c bridge.c vlan.c ubus.c)

SET(LIBS
	ubox ubus uci json blobmsg_json)

IF (NOT DEFINED LIBNL_LIBS)
  SET(LIBNL_LIBS -lnl)
ENDIF()

IF("${CMAKE_SYSTEM_NAME}" MATCHES "Linux" AND NOT DUMMY_MODE)
	SET(SOURCES ${SOURCES} system-linux.c)
	SET(LIBS ${LIBS} ${LIBNL_LIBS})
ELSE()
	ADD_DEFINITIONS(-DDUMMY_MODE=1)
	SET(SOURCES ${SOURCES} system-dummy.c)
ENDIF()

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()


ADD_EXECUTABLE(netifd ${SOURCES})

TARGET_LINK_LIBRARIES(netifd ${LIBS})

INSTALL(TARGETS netifd
	RUNTIME DESTINATION sbin
)
