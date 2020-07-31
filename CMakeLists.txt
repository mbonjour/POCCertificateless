cmake_minimum_required(VERSION 3.10)
project(POCCertificatelessCryptography C)

set(CMAKE_C_STANDARD 11)
link_libraries(asan)
include_directories(. ${CMAKE_SOURCE_DIR}/libs/relic/include ${CMAKE_SOURCE_DIR}/libs/unqlite ${CMAKE_SOURCE_DIR}/libs/relic-target/include ${CMAKE_SOURCE_DIR}/libs/binn)

link_libraries(${CMAKE_SOURCE_DIR}/libs/relic-target/lib/librelic.so)
link_libraries(${CMAKE_SOURCE_DIR}/libs/unqlite/libunqlite.a)
link_libraries(sodium)
#link_libraries(nsl)
link_libraries(pthread)
link_libraries(curl)
link_libraries(etpan)

link_libraries(${CMAKE_SOURCE_DIR}/libs/binn/libbinn.so.3.0)
#link_libraries(binn)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -g -fno-omit-frame-pointer")
set(COMMON_SOURCES cipherPOC.c cipherPOC.h signaturePOC.c signaturePOC.h utils/base64.c utils/base64.h utils/socketUtils.c utils/socketUtils.h)
set(CLIENT_SOURCES client/mainClient.c utils/aesUtils.c utils/aesUtils.h client/mainClient.h)
set(SERVER_SOURCES server/mainServer.c)
set(TEST_SOURCES test/fullTest.c utils/aesUtils.c utils/aesUtils.h)

add_definitions("-Wall -Wextra -Wpedantic ")
# -Wformat=2 -Wno-unused-parameter -Wshadow -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wredundant-decls -Wnested-externs -Wmissing-include-dirs

add_executable(mainClient ${CLIENT_SOURCES} ${COMMON_SOURCES})
add_executable(mainServer ${SERVER_SOURCES} ${COMMON_SOURCES})
add_executable(testAlgo ${TEST_SOURCES} ${COMMON_SOURCES})