# cmake/CUDAUtils.cmake
# Configures CUDA Architectures and Compute Sanitizer Flags

function(configure_cuda_target TARGET_NAME)
    if(NOT CMAKE_CUDA_COMPILER)
        message(FATAL_ERROR "[sentinel-rt] CUDA compiler (nvcc) not found.")
        return()
    endif()

    # Target modern architectures: Ampere (sm_80, sm_86), Ada (sm_89), Hopper (sm_90)
    set_target_properties(${TARGET_NAME} PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON
        CUDA_RESOLVE_DEVICE_SYMBOLS ON
    )

    # Enable line-info for CUDA debugging & profiling without disabling optimization
    target_compile_options(${TARGET_NAME} PRIVATE
        $<$<COMPILE_LANGUAGE:CUDA>:
            --generate-line-info
            -Xcompiler=-Wall
            -Xcompiler=-Wextra
        >
    )
endfunction()