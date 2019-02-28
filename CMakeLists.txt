project (test_libotr)
cmake_minimum_required (VERSION 2.8)

set (PROJECT_NAME "test-libotr")

set (CMAKE_C_STANDARD 99)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W -Wall")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fstack-protector-all")

include_directories(${CMAKE_BINARY_DIR})
add_executable (${PROJECT_NAME} test-otr-key-generation.c)

if (WIN32)
    set (EXTRA_LIBS "intl -liconv -lws2_32")
endif ()
target_link_libraries (${PROJECT_NAME} otr gcrypt gpg-error ${EXTRA_LIBS})

install (TARGETS ${PROJECT_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}/")

