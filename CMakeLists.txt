cmake_minimum_required(VERSION 2.6)

PROJECT(netifd C)
ADD_DEFINITIONS(-Os -Wall -Werror)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

SET(SOURCES
	main.c utils.c interface.c interface-ip.c
	proto.c proto-static.c proto-shell.c
	config.c device.c bridge.c vlan.c ubus.c)

SET(LIBS
	ubox ubus uci json blobmsg_json)

IF("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")
	SET(SOURCES ${SOURCES} system-linux.c)
	SET(LIBS ${LIBS} nl)
ELSE()
	SET(SOURCES ${SOURCES} system-dummy.c)
ENDIF()

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -O0 --std=gnu99 -g3)
ENDIF()


ADD_EXECUTABLE(netifd ${SOURCES})

TARGET_LINK_LIBRARIES(netifd ${LIBS})
