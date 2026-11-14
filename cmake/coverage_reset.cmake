# Delete every .gcda counter file under DIR (target `coverage-reset`).
file(GLOB_RECURSE _gcda "${DIR}/*.gcda")
if(_gcda)
    file(REMOVE ${_gcda})
endif()
list(LENGTH _gcda _n)
message(STATUS "coverage-reset: removed ${_n} .gcda file(s)")
