cmake_minimum_required(VERSION 2.6)

PROJECT(netifd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -O0)
ENDIF()

ADD_EXECUTABLE(netifd main.c interface.c proto.c config.c device.c bridge.c vlan.c ubus.c system-dummy.c)
TARGET_LINK_LIBRARIES(netifd ubox ubus uci)
