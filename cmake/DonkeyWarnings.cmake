# Project-owned warning policy. Applied only to Donkey targets, never to
# third-party targets (those are marked SYSTEM via FetchContent or built with
# their own settings).

add_library(donkey_project_warnings INTERFACE)

if(MSVC)
  target_compile_options(donkey_project_warnings INTERFACE
    /W4
    /permissive-
    /Zc:__cplusplus
    /utf-8
  )
  if(DONKEY_WARNINGS_AS_ERRORS)
    target_compile_options(donkey_project_warnings INTERFACE /WX)
  endif()
else()
  target_compile_options(donkey_project_warnings INTERFACE
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Wcast-align
    -Wunused
    -Woverloaded-virtual
    -Wnull-dereference
    -Wdouble-promotion
  )
  if(DONKEY_WARNINGS_AS_ERRORS)
    target_compile_options(donkey_project_warnings INTERFACE -Werror)
  endif()
endif()

function(donkey_apply_warnings target)
  target_link_libraries(${target} PRIVATE donkey_project_warnings)
endfunction()
