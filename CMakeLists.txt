cmake_minimum_required(VERSION 3.10)

project(HOMOZUC)

add_executable(testzuc zuctest.c zuc.c)

add_executable(homoZUC zuc.c homozuc.cpp)

target_link_libraries(homoZUC tfhe-spqlios-fma)
