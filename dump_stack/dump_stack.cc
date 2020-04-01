#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <unistd.h>
#include <cstring>
#include <utility>
#include <array>
#include <cassert>
#include <limits>
#include <charconv>

#include "print.cc"

/***************************** DESCRIPTION OF STACK FORMAT *****************************
 * source: https://lwn.net/Articles/631631/
    ------------------------------------------------------------- 0x7fff6c845000
     0x7fff6c844ff8: 0x0000000000000000
            _  4fec: './stackdump\0'                      <------+
      env  /   4fe2: 'ENVVAR2=2\0'                               |    <----+
           \_  4fd8: 'ENVVAR1=1\0'                               |   <---+ |
           /   4fd4: 'two\0'                                     |       | |     <----+
     args |    4fd0: 'one\0'                                     |       | |    <---+ |
           \_  4fcb: 'zero\0'                                    |       | |   <--+ | |
               3020: random gap padded to 16B boundary           |       | |      | | |
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|       | |      | | |
               3019: 'x86_64\0'                        <-+       |       | |      | | |
     auxv      3009: random data: ed99b6...2adcc7        | <-+   |       | |      | | |
     data      3000: zero padding to align stack         |   |   |       | |      | | |
    . . . . . . . . . . . . . . . . . . . . . . . . . . .|. .|. .|       | |      | | |
               2ff0: AT_NULL(0)=0                        |   |   |       | |      | | |
               2fe0: AT_PLATFORM(15)=0x7fff6c843019    --+   |   |       | |      | | |
               2fd0: AT_EXECFN(31)=0x7fff6c844fec      ------|---+       | |      | | |
               2fc0: AT_RANDOM(25)=0x7fff6c843009      ------+           | |      | | |
      ELF      2fb0: AT_SECURE(23)=0                                     | |      | | |
    auxiliary  2fa0: AT_EGID(14)=1000                                    | |      | | |
     vector:   2f90: AT_GID(13)=1000                                     | |      | | |
    (id,val)   2f80: AT_EUID(12)=1000                                    | |      | | |
      pairs    2f70: AT_UID(11)=1000                                     | |      | | |
               2f60: AT_ENTRY(9)=0x4010c0                                | |      | | |
               2f50: AT_FLAGS(8)=0                                       | |      | | |
               2f40: AT_BASE(7)=0x7ff6c1122000                           | |      | | |
               2f30: AT_PHNUM(5)=9                                       | |      | | |
               2f20: AT_PHENT(4)=56                                      | |      | | |
               2f10: AT_PHDR(3)=0x400040                                 | |      | | |
               2f00: AT_CLKTCK(17)=100                                   | |      | | |
               2ef0: AT_PAGESZ(6)=4096                                   | |      | | |
               2ee0: AT_HWCAP(16)=0xbfebfbff                             | |      | | |
               2ed0: AT_SYSINFO_EHDR(33)=0x7fff6c86b000                  | |      | | |
    . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .        | |      | | |
               2ec8: environ[2]=(nil)                                    | |      | | |
               2ec0: environ[1]=0x7fff6c844fe2         ------------------|-+      | | |
               2eb8: environ[0]=0x7fff6c844fd8         ------------------+        | | |
               2eb0: argv[3]=(nil)                                                | | |
               2ea8: argv[2]=0x7fff6c844fd4            ---------------------------|-|-+
               2ea0: argv[1]=0x7fff6c844fd0            ---------------------------|-+
               2e98: argv[0]=0x7fff6c844fcb            ---------------------------+
     0x7fff6c842e90: argc=3
*/

template<typename T>
inline auto consume(std::byte *&ptr, std::size_t bytes = sizeof(T))
  -> std::add_lvalue_reference_t<T>
{
  return *reinterpret_cast<std::add_pointer_t<T>>(std::exchange(ptr, ptr + bytes));
}

void Main(std::byte *stack)
{
  auto stack_ptr = stack;
  [[maybe_unused]] auto argc = consume<int64_t>(stack_ptr);

  auto print_null_terminated_list = [&](auto &header)
  {
    println(header);
    while (auto const element = consume<char const*>(stack_ptr))
      println(element);
  };

  print_null_terminated_list("\n\n----------- Argument -----------");
  print_null_terminated_list("\n\n---------- Enviroment ----------");

  println("\n\n------- Auxiliary Vector -------");

  std::array<std::byte, 16> *random_bytes = nullptr;

  for (;;) {
    const auto [identifier, value] = consume<std::array<std::uint64_t, 2>>(stack_ptr, 16);    
    auto const print = [value](auto &&str, auto... p)
    {
      ::print(str);
      if constexpr (sizeof...(p) >= 1)
        ::println((char const*) value);
      else
        ::println(value, 16);
    };


    switch (identifier) {
      case 0:  print("AT_NULL         "); goto end_loop;
      
      // address of program headers of the executable
      case 3:  print("AT_PHDR         "); break;
      // size of program header entry
      case 4:  print("AT_PHENT        "); break;
      // number of program headers
      case 5:  print("AT_PHNUM        "); break;
      // system page size
      case 6:  print("AT_PAGESZ       "); break;
      // the base address of the program interpreter
      case 7:  print("AT_BASE         "); break;
      // currently unused
      case 8:  print("AT_FLAGS        "); break;
      // entry address of executable
      case 9:  print("AT_ENTRY        "); break;
      // real user id
      case 11: print("AT_UID          "); break;
      // effective user id
      case 12: print("AT_EUID         "); break;
      // real group id
      case 13: print("AT_GID          "); break;
      // real effective group id
      case 14: print("AT_EGID         "); break;

      case 15: print("AT_PLATFORM     ", 0); break;
      
      // multibyte mask of bits whose settings indicate detailed processor
      // capabilities. Can be use for optimization of some library functions.
      // Content of this bit mask is hardware dependent, list of flags is in
      // arch/x86/include/asm/cpufeature.h
      case 16: print("AT_HWCAP        "); break;
      // number of clock ticks per second (connected to times() from sys/times.h)
      case 17: print("AT_CLKTCK       "); break;
      
      // has a nonzero value if this executable should be treated securely.
      // nonzero value makes dynamic linker disable access to some environmental variables
      // glibc also behaves differently (secure_getenv() tightly connected)
      // see man 8 ld-linux.so
      case 23: print("AT_SECURE       "); break;

      // pathname used to execute program
      case 31: print("AT_EXECFN       "); break;

      // address of a page containing the virtual Dynamic Shared Object used by 
      // the kernel in order to provide fast implementations of some system calls.
      case 33: print("AT_SYSINFO_EHDR "); break;
      
      case 25: 
        print("AT_RANDOM       ");
        random_bytes = (decltype(random_bytes)) value;          
        break;
      
      default:
        ::print("unrecognized id: ");
        println(identifier);
        return;
    }
  } end_loop:;
  print("\n");

  // kernel writes 16 random bytes (not know that they are crypto safe)
  // they are used by dynamic linker to implement stack canaries
  // https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries
  println("\n\n-------- 16 Random Bytes -------");
  for (auto i = 0u; i < 16; ++i) {
    print("\n " + (i != 8));
    print(static_cast<uint8_t>((*random_bytes)[i]), 16);
  }
  println();
}

template<typename F, typename Default, typename... Args>
static decltype(auto) get_or_default(F&& func, Default&& def, Args&&... args)
{
  if constexpr (std::is_invocable_r_v<Default, F, Args...>)
    return std::forward<F>(func)(std::forward<Args>(args)...);
  else { 
    static_assert(std::is_void_v<std::invoke_result_t<F, Args...>>);
    std::forward<F>(func)(std::forward<Args>(args)...); 
    return std::forward<Default>(def); 
  }
}

extern "C" {
  void _start() 
  {
    exit(get_or_default(Main, 0, (std::byte*)__builtin_frame_address(0) + 8));
  }
}

