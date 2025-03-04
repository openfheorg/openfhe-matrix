cmake_minimum_required (VERSION 3.5.1)

project (OpenFHE-Pymat)
set(OPENFHE_PYMAT_VERSION_MAJOR 0)
set(OPENFHE_PYMAT_VERSION_MINOR 0)
set(OPENFHE_PYMAT_VERSION_PATCH 1)
set(OPENFHE_PYMAT_VERSION ${OPENFHE_PYTHON_VERSION_MAJOR}.${OPENFHE_PYTHON_VERSION_MINOR}.${OPENFHE_PYTHON_VERSION_PATCH})

set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

if(APPLE)
    set(CMAKE_CXX_VISIBILITY_PRESET default)
endif()

find_package(OpenFHE 1.1.2 REQUIRED)
find_package(pybind11 REQUIRED)
# Find a package
# find_package(OpenFHE-MATRIX REQUIRED)

set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )

set( OpenFHE_Matrix_INCLUDES  ${CMAKE_INSTALL_PREFIX}/include/openfhe_matrix)


include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/binfhe )
include_directories( ${OpenFHE_Matrix_INCLUDES} )


### add directories for other OpenFHE modules as needed for your project


link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif()

### Pybind Modules
pybind11_add_module(openfhe_matrix bindings.cpp)

### Python installation 
# Allow the user to specify the path to Python executable (if not provided, find it)
option(PYTHON_EXECUTABLE_PATH "Path to Python executable" "")

if(NOT PYTHON_EXECUTABLE_PATH)
    # Find Python and its development components
    find_package(Python REQUIRED COMPONENTS Interpreter Development)
else()
    # Set Python_EXECUTABLE to the specified path
    set(Python_EXECUTABLE "${PYTHON_EXECUTABLE_PATH}")
endif()

# Find Python interpreter
find_package(PythonInterp REQUIRED)

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

# add_executable(simple_demo tests/simple_demo.py)
# target_link_libraries(simple_demo PRIVATE OpenFHE-Pymat)

# Add the library source files
message("***** CMAKE_SOURCE_DIR = ${CMAKE_SOURCE_DIR}")

message(STATUS "Python site packages directory: ${PYTHON_SITE_PACKAGES}")
install(TARGETS openfhe_matrix LIBRARY DESTINATION ${PYTHON_SITE_PACKAGES})

