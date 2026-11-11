# Fails if a static archive references functions that the sans-I/O core must
# not use: system call wrappers, clocks, random sources, threads, stdio and
# iostreams. Usage:
#   cmake -DNM=<nm> -DARCHIVE=<lib.a> [-DEXPECT=<name,...>] -P CheckCoreSymbols.cmake
# Prints "forbidden symbol: <name>" for each hit. Without EXPECT it exits
# non-zero if there is any hit. With EXPECT (used to test this script) it
# exits non-zero unless every listed name is among the hits.

if(NOT NM OR NOT ARCHIVE)
  message(FATAL_ERROR "usage: cmake -DNM=<nm> -DARCHIVE=<archive> -P CheckCoreSymbols.cmake")
endif()

execute_process(
  COMMAND ${NM} -C -u ${ARCHIVE}
  OUTPUT_VARIABLE nm_out
  ERROR_VARIABLE nm_err
  RESULT_VARIABLE nm_rc)
if(NOT nm_rc EQUAL 0)
  message(FATAL_ERROR "${NM} failed on ${ARCHIVE}: ${nm_err}")
endif()

# C functions, matched against the whole symbol name.
set(c_names
  open openat openat2 creat close read write pread pwrite readv writev preadv pwritev
  lseek ioctl fcntl dup dup2 dup3 pipe pipe2 poll ppoll select pselect
  socket socketpair bind connect listen accept accept4 shutdown
  send sendto sendmsg sendmmsg recv recvfrom recvmsg recvmmsg setsockopt getsockopt
  mmap munmap mprotect madvise brk sbrk
  clock_gettime clock_nanosleep gettimeofday time nanosleep usleep sleep
  timerfd_create timerfd_settime timerfd_gettime eventfd signalfd
  getrandom getentropy rand rand_r srand random srandom drand48 arc4random
  syscall fork vfork clone execve kill raise signal sigaction getpid gettid
  fopen fdopen fclose fread fwrite fflush fprintf printf vprintf vfprintf puts fputs putchar
  getenv setenv putenv)
list(JOIN c_names "|" c_alt)
set(c_regex "^(${c_alt})(64)?$")
set(prefix_regex "^(epoll_|io_uring_|pthread_|thrd_|mtx_|cnd_|aio_)")
set(cxx_regex
  "^std::(random_device|thread|jthread|mutex|recursive_mutex|shared_mutex|timed_mutex|condition_variable|this_thread|cout|cerr|clog|cin|wcout|wcerr|basic_filebuf|basic_ifstream|basic_ofstream|basic_fstream|vprint_|__open_terminal|__write_to_terminal)|^std::chrono::(_V2::)?(system_clock|steady_clock|high_resolution_clock)::now")

string(REPLACE "\n" ";" lines "${nm_out}")
set(hits "")
foreach(line IN LISTS lines)
  string(STRIP "${line}" line)
  if(NOT line MATCHES "^U ")
    continue()
  endif()
  string(SUBSTRING "${line}" 2 -1 sym)
  # Demangled C++ names carry their parameter list; match on the name only.
  string(REGEX REPLACE "\\(.*$" "" name "${sym}")
  if(name MATCHES "${c_regex}" OR name MATCHES "${prefix_regex}" OR name MATCHES "${cxx_regex}")
    list(APPEND hits "${sym}")
  endif()
endforeach()

list(REMOVE_DUPLICATES hits)
foreach(h IN LISTS hits)
  message("forbidden symbol: ${h}")
endforeach()

if(DEFINED EXPECT)
  string(REPLACE "," ";" expect_list "${EXPECT}")
  foreach(want IN LISTS expect_list)
    set(found FALSE)
    foreach(h IN LISTS hits)
      string(FIND "${h}" "${want}" pos)
      if(pos EQUAL 0)
        set(found TRUE)
      endif()
    endforeach()
    if(NOT found)
      message(FATAL_ERROR "expected a forbidden symbol starting with '${want}', none reported")
    endif()
  endforeach()
  message("all expected forbidden symbols reported")
  return()
endif()

if(hits)
  message(FATAL_ERROR "${ARCHIVE} references functions the core must not use")
endif()
message("${ARCHIVE}: no forbidden symbols")
