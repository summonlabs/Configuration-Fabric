# Compiler warning policy for first-party code.
#
# Configuration Fabric is held to a zero first-party warning count. Warnings are
# promoted to errors by default (CF_WARNINGS_AS_ERRORS=ON) so that a build cannot
# silently regress. Third-party code is not compiled as part of this project.

include_guard(GLOBAL)

function(cf_set_project_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4
      /permissive-
      /Zc:__cplusplus
      /Zc:preprocessor
      /utf-8
      /EHsc
      /MP
    )
    if(CF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wshadow
      -Wnon-virtual-dtor
      -Wcast-align
      -Wunused
      -Woverloaded-virtual
      -Wnull-dereference
      -Wdouble-promotion
    )
    if(CF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

function(cf_enable_sanitizers target)
  if(NOT CF_ENABLE_ASAN)
    return()
  endif()
  if(MSVC)
    target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
    target_link_options(${target} PRIVATE /INCREMENTAL:NO)
  else()
    target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address)
  endif()
endfunction()
