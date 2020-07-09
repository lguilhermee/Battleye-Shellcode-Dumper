#pragma once

#include <string>
#ifdef _MSC_VER
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE __attribute__((always_inline))
#endif


template<typename T, size_t L>
class XorStrEx
{
    static constexpr auto kLengthMinusOne = L - 1;

public:
    constexpr ALWAYS_INLINE XorStrEx(T const (&str)[L])
        : XorStrEx(str, std::make_index_sequence<kLengthMinusOne>())
    {
    }

    auto c_str_raw() const
    {
        return data;
    }

    auto c_str() const
    {
        decrypt();
        return data;
    }

    auto str() const
    {
        decrypt();
        return std::basic_string<T>(data, data + kLengthMinusOne);
    }

    operator std::basic_string<T>() const
    {
        return str();
    }

    void encrypt() const
    {
        if (!encrypted)
        {
            xorData();
            encrypted = true;
        }
    }

    void decrypt() const
    {
        if (encrypted)
        {
            xorData();
            encrypted = false;
        }
    }

private:
    mutable T data[L];
    mutable bool encrypted;

    template<size_t... indices>
    constexpr ALWAYS_INLINE XorStrEx(T const (&str)[L], std::index_sequence<indices...>)
        : data{ xorChar(str[indices], indices)..., '\0' },
        encrypted(true)
    {
    }

    static ALWAYS_INLINE constexpr int atoi(char c)
    {
        return c - '0';
    }

    static constexpr auto RANDOM_XOR_KEY = static_cast<T>(
        atoi(__TIME__[7]) +
        atoi(__TIME__[6]) * 10 +
        atoi(__TIME__[4]) * 60 +
        atoi(__TIME__[3]) * 600 +
        atoi(__TIME__[1]) * 3600 +
        atoi(__TIME__[0]) * 36000
        );

    static ALWAYS_INLINE constexpr auto xorChar(T c, size_t i)
    {
        return static_cast<T>(c ^ (RANDOM_XOR_KEY + i));
    }

    void xorData() const
    {
        for (size_t t = 0; t < kLengthMinusOne; t++)
        {
            data[t] = xorChar(data[t], t);
        }
    }
};
//---------------------------------------------------------------------------
template<size_t L>
using XorStrA = XorStrEx<char, L>;
template<size_t L>
using XorStrW = XorStrEx<wchar_t, L>;
//---------------------------------------------------------------------------
template<typename T, size_t L>
constexpr ALWAYS_INLINE auto xorstr_(const T(&str)[L])
{
    return XorStrEx<T, L>(str);
}



template<typename T, size_t L, size_t LC>
auto operator==(const XorStrEx<T, L>& lhs, const XorStrEx<T, LC>& rhs)
{
    static_assert(L == LC, "XorStrEx length is different");

    return L == LC && lhs.str() == rhs.str();
}

template<typename T, size_t L>
auto operator==(const T& lhs, const XorStrEx<T, L>& rhs)
{
    return lhs.size() == L && lhs == rhs.str();
}

template<typename ST, typename T, size_t L>
auto& operator<<(ST& lhs, const XorStrEx<T, L>& rhs)
{
    lhs << rhs.c_str();

    return lhs;
}

template<typename T, size_t L, size_t LC>
auto operator+(const XorStrEx<T, L>& lhs, const XorStrEx<T, LC>& rhs)
{
    return lhs.str() + rhs.str();
}

template<typename T, size_t L>
auto operator+(const T& lhs, const XorStrEx<T, L>& rhs)
{
    return lhs + rhs.str();
}