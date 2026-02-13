# SM4-BGV Transciphering Implementation (HElib-based)

This project provides an implementation of **SM4-to-BGV transciphering**
based on the HElib library.\
The implementation is located under:

    example/BGV_sm4/

The code demonstrates homomorphic transciphering from **SM4-CTR
ciphertexts** to **BGV ciphertexts**, together with performance
benchmarks for key building blocks.

------------------------------------------------------------------------

## Overview

This project implements:

-   SM4-CTR based transciphering under the BGV homomorphic encryption
    scheme
-   Homomorphic evaluation of one complete SM4 round function
-   Performance benchmarking of major building blocks
-   Multi-threaded execution based on NTL + pthread

The implementation is built on top of HElib and leverages its BGV
functionality.

------------------------------------------------------------------------

## Project Structure

    example/
     └── BGV_sm4/
     	  ├── BGV_sm4.h
          ├── BGV_sm4.cpp        # Complete SM4-CTR transciphering (one round function)
          ├── benchmark.cpp      # Benchmarking for building blocks
          └── CMakeLists.txt

### File Descriptions

#### BGV_sm4.cpp

Implements:

-   Parameter setup for BGV
-   Encryption of SM4 round keys
-   Homomorphic evaluation of the SM4 round function
-   CTR-mode style transciphering workflow

This file demonstrates a complete SM4-CTR transciphering pipeline under
BGV.

------------------------------------------------------------------------

#### benchmark.cpp

Provides performance measurements for:

-   Homomorphic addition and multiplication
-   S-box related building blocks
-   Linear transformation components
-   Other core operations used in transciphering

This file is intended for profiling and performance evaluation.

------------------------------------------------------------------------

## Dependencies

The project depends on:

-   HElib
-   NTL
-   pthread

Ensure that HElib is correctly installed and linked before building this
project.

------------------------------------------------------------------------

## Build Instructions

### Step 1: Build HElib

Follow the official instructions from the HElib repository:

    git clone https://github.com/homenc/HElib.git
    cd HElib
    mkdir build && cd build
    cmake ..
    make
    sudo make install

Ensure that:

-   NTL and GMP are installed
-   HElib builds successfully

------------------------------------------------------------------------

### Step 2: Build the SM4--BGV Example

Navigate to the `example` directory:

    cd example
    mkdir build
    cd build
    cmake ..
    make

After successful compilation, the executable files will be generated in
the `build` directory.

------------------------------------------------------------------------

## Running

Inside `example/build`:

    ./BGV_sm4

or

    ./bench

Depending on which target is built.

------------------------------------------------------------------------

## Multi-threading Support

This project supports multi-threaded execution via:

-   NTL thread support
-   POSIX pthread

Thread configuration depends on:

-   NTL build configuration
-   System-level thread support

Ensure that NTL is compiled with thread support enabled.

------------------------------------------------------------------------

## Experimental Purpose

This implementation is intended for:

-   Research on SM4 transciphering
-   Evaluation of homomorphic building blocks
-   Performance benchmarking under BGV
-   Studying noise growth and multiplicative depth behavior

------------------------------------------------------------------------

## License

Specify your license here (e.g., MIT / GPL / Apache 2.0).

------------------------------------------------------------------------

## Citation

If you use this implementation in academic work, please cite the
corresponding paper.
