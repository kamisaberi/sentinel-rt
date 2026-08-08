# cmake/Sanitizers.cmake
# Configures LLVM/GCC Sanitizer flags for sentinel-rt

function(enable_sanitizers TARGET_NAME)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(WARNING "[sentinel-rt] Sanitizers are only supported on Clang and GCC.")
        return()
    endif()

    set(SANITIZER_FLAGS "")

    if(SENTINEL_ENABLE_ASAN)
        message(STATUS "[sentinel-rt] Adding AddressSanitizer to ${TARGET_NAME}")
        list(APPEND SANITIZER_FLAGS "-fsanitize=address" "-fno-omit-frame-pointer")
    endif()

    if(SENTINEL_ENABLE_UBSAN)
        message(STATUS "[sentinel-rt] Adding UndefinedBehaviorSanitizer to ${TARGET_NAME}")
        list(APPEND SANITIZER_FLAGS "-fsanitize=undefined" "-fno-sanitize-recover=all")
    endif()

    if(SENTINEL_ENABLE_TSAN)
        if(SENTINEL_ENABLE_ASAN)
            message(FATAL_ERROR "[sentinel-rt] ASan and TSan cannot be enabled simultaneously.")
        endif()
        message(STATUS "[sentinel-rt] Adding ThreadSanitizer to ${TARGET_NAME}")
        list(APPEND SANITIZER_FLAGS "-fsanitize=thread")
    endif()

    target_compile_options(${TARGET_NAME} PRIVATE ${SANITIZER_FLAGS})
    target_link_options(${TARGET_NAME} PRIVATE ${SANITIZER_FLAGS})
endfunction()