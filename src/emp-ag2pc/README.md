# EMP-ag2pc
![arm](https://github.com/emp-toolkit/emp-ag2pc/workflows/arm/badge.svg)
![x86](https://github.com/emp-toolkit/emp-ag2pc/workflows/x86/badge.svg)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/emp-toolkit/emp-ag2pc.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/emp-toolkit/emp-ag2pc/alerts/)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/emp-toolkit/emp-ag2pc.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/emp-toolkit/emp-ag2pc/context:cpp)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

Authenticated Garbling and Efficient Maliciously Secure Two-Party Computation. More details of the protocol can be found in the [paper](https://eprint.iacr.org/2017/030).

# Installation
1. `wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py`
2. `python install.py --install --tool --ot --ag2pc`
    1. By default it will build for Release. `-DCMAKE_BUILD_TYPE=[Release|Debug]` option is also available.
    2. No sudo? Change [`CMAKE_INSTALL_PREFIX`](https://cmake.org/cmake/help/v2.8.8/cmake.html#variable%3aCMAKE_INSTALL_PREFIX).


## Test

* If you want to test the code in local machine, type

   `./run ./bin/[binaries] 12345 [more opts]`
* IF you want to test the code over two machine, type

  `./bin/[binaries] 1 12345 [more opts]` on one machine and 
  
  `./bin/[binaries] 2 12345 [more opts]` on the other.
  
  IP address is hardcoded in the test files. Please replace
  IP variable to the real ip.

### Question
Please send email to wangxiao1254@gmail.com

## Acknowledgement
This work was supported in part by the National Science Foundation under Awards #1111599 and #1563722.

## Adjustments
Please note that this version of emp-ag2pc has been adjusted as to not use the thread pool. This may make certain operation slower. 

