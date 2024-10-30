cmake_minimum_required(VERSION 3.23)

if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

add_library(dr_client SHARED main.cpp itree.cpp)

find_package(DynamoRIO)

if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
endif (NOT DynamoRIO_FOUND)

configure_DynamoRIO_client(dr_client)

use_DynamoRIO_extension(dr_client drmgr)
use_DynamoRIO_extension(dr_client drwrap)