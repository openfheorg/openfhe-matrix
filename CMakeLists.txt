cmake_minimum_required (VERSION 3.5.1)

project(openfhe_matrix)
set(OPENFHE_MATRIX_VERSION_MAJOR 0)
set(OPENFHE_MATRIX_VERSION_MINOR 0)
set(OPENFHE_MATRIX_VERSION_PATCH 1)
set(OPENFHE_MATRIX_VERSION ${OPENFHE_MATRIX_VERSION_MAJOR}.${OPENFHE_MATRIX_VERSION_MINOR}.${OPENFHE_MATRIX_VERSION_PATCH})

set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE 1.2.3 CONFIG REQUIRED)

# "CMAKE_INTERPROCEDURAL_OPTIMIZATION ON" (ON is the default value) causes link failure. see
# https://github.com/openfheorg/openfhe-python/actions/runs/11492843373/job/31987579944
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)

set( OpenFHE_Matrix_SOURCES cpp/src)
set( OpenFHE_Matrix_INCLUDES cpp/include)

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/binfhe )
# include_directories( ${OpenFHE_Py_SOURCES} )
include_directories( ${OpenFHE_Matrix_INCLUDES} )

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif()

file (GLOB_RECURSE SOURCES CONFIGURE_DEPENDS ${OpenFHE_Matrix_SOURCES}/*.cpp)

### Pybind Modules
# finding pybind11 is a bit tricky
# capture the output of the following python command
execute_process(
    COMMAND python${APSI_PYTHON_VERSION} -m pybind11 --includes
    OUTPUT_VARIABLE PYBIND11_INCLUDES
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# remove the "-I" prefixes
string(REPLACE "-I" "" PYBIND11_PATHS "${PYBIND11_INCLUDES}")
# get the path including "pybind11/include"
string(REGEX MATCH "[^ ]+/pybind11/include" PYBIND11_INCLUDE_PATH "${PYBIND11_PATHS}")

include_directories(${PYBIND11_INCLUDE_PATH})
message(STATUS "PYBIND11 include path: ${PYBIND11_INCLUDE_PATH}")

find_package(pybind11 REQUIRED)
pybind11_add_module(openfhe_matrix ${SOURCES})

### Python installation 
# Allow the user to specify the path to Python executable (if not provided, find it)
option(PYTHON_EXECUTABLE_PATH "Path to Python executable" "")

if(NOT PYTHON_EXECUTABLE_PATH)
    # Find Python and its development components
    find_package (Python3 3.12 EXACT COMPONENTS Interpreter Development REQUIRED)
    # find_package(Python3 REQUIRED COMPONENTS Interpreter Development)
else()
    # Set Python_EXECUTABLE to the specified path
    set(Python_EXECUTABLE "${PYTHON_EXECUTABLE_PATH}")
endif()

# Check Python version
if(${PYTHON_VERSION_MAJOR} EQUAL 3 AND ${PYTHON_VERSION_MINOR} GREATER_EQUAL 10)
    execute_process(
        COMMAND "${Python_EXECUTABLE}" -c "from sys import exec_prefix; print(exec_prefix)"
        OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
else()
    execute_process(
        COMMAND "${Python_EXECUTABLE}" -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
        OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

message(STATUS "Python site packages directory: ${PYTHON_SITE_PACKAGES}")
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(Python_Install_Location "${PYTHON_SITE_PACKAGES}")
else()
    set(Python_Install_Location "${CMAKE_INSTALL_PREFIX}")
endif()
message("***** INSTALL IS AT ${Python_Install_Location}; to change, run cmake with -DCMAKE_INSTALL_PREFIX=/your/path")
install(TARGETS openfhe_matrix LIBRARY DESTINATION ${Python_Install_Location})


