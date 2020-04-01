template<std::size_t N>
inline void print(char const (&str)[N])
{
  write(1, const_cast<char*>(str), N);
}

inline void print(char const* str)
{
  write(1, str, strlen(str));
}

template<typename T> requires std::is_integral_v<T>
void print(T numeric, std::size_t base = 10)
{
  constexpr auto capacity = std::numeric_limits<T>::digits10 + std::is_signed_v<T>;
  std::array<char, capacity> buffer;
  auto begin = std::data(buffer);
  auto [ptr, ec] = std::to_chars(begin, begin + capacity, numeric, base);
  if (ec != std::errc{})
    return;
  write(1, begin, ptr - begin);
}

template<typename ...T>
inline void println(T&& ...val)
{
  if constexpr (sizeof...(T) > 0)
    print(std::forward<T>(val)...);
  write(1, "\n", 1);
}