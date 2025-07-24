cmake_minimum_required(VERSION 3.5)
project(ptt-lib C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
find_package(PkgConfig REQUIRED)
pkg_check_modules(KRB5 REQUIRED krb5)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${KRB5_INCLUDE_DIRS}
)

link_directories(${KRB5_LIBRARY_DIRS})
set(SOURCES
  ptt.c
  kerb_reader.c
  exporter.c
)

add_library(ptt SHARED ${SOURCES})
target_compile_definitions(ptt PRIVATE PTT_EXPORTS)
target_link_libraries(ptt ${KRB5_LIBRARIES})

set_target_properties(ptt PROPERTIES
  VERSION     1.0.0
  SOVERSION   1
)

install(TARGETS ptt
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  PUBLIC_HEADER DESTINATION include
)
