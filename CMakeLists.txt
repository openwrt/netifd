cmake_minimum_required(VERSION 2.6)

PROJECT(netifd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -O0)
ENDIF()


ADD_EXECUTABLE(netifd
	main.c utils.c interface.c interface-ip.c
	proto.c proto-static.c proto-shell.c
	config.c device.c bridge.c vlan.c ubus.c
	system-dummy.c)

TARGET_LINK_LIBRARIES(netifd ubox ubus uci json)
