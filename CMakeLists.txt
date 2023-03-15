project(userdbmanager)
cmake_minimum_required(VERSION 3.0)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/")
FIND_PACKAGE(BerkeleyDB REQUIRED)
FIND_PACKAGE(Crypt   ) 

add_executable(userdbmanager main.c)
#target_link_libraries(userdbmanager PRIVATE Oracle::BerkeleyDB)#target_link_libraries(userdbmanager PRIVATE Oracle::BerkeleyDB)
target_link_libraries(userdbmanager PRIVATE ${BerkeleyDB_LIBRARY} crypt ${Crypt_LIBRARY} )
