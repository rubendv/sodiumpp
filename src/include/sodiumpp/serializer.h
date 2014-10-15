#pragma once
#include <string>
#include <type_traits>
#include <sstream>

namespace sodiumpp {
    class archive {
    public:
        std::stringstream stream;
        template <typename T>
        typename std::enable_if<std::is_integral<T>::value, archive&>::type operator<<(T x) {
            for(size_t i = 0; i < sizeof(x); ++i) {
                stream.put((x >> (sizeof(x)-1-i)) & 0xff);
            }
            return *this;
        }
        template <typename T>
        typename std::enable_if<std::is_integral<T>::value, archive&>::type operator>>(T& x) {
            x = 0;
            for(size_t i = 0; i < sizeof(x); ++i) {
                x |= stream.get() << (sizeof(x)-1-i);
            }
            return *this;
        }
        template <typename T>
        typename std::enable_if<std::is_floating_point<T>::value, archive&>::type operator<<(T x) {
            union {
                T x;
                char[sizeof(x)] bytes;
            } convert;
            convert.x = x;
            stream.write(&convert.bytes[0], sizeof(x));
            return *this;
        }
        template <typename T>
        typename std::enable_if<std::is_floating_point<T>::value, archive&>::type operator>>(T& x) {
            union {
                T x;
                char[sizeof(x)] bytes;
            } convert;
            stream.read(&convert.bytes[0], sizeof(x));
            x = convert.x;
            return *this;
        }
        archive& operator<<(const std::string& bytes) {
            *this << bytes.size();
            stream.write(&bytes[0], bytes.size());
            return *this;
        }
        archive& operator>>(const std::string& bytes) {
            decltype(bytes.size()) size;
            *this >> size;
            bytes.resize(size);
            stream.read(&bytes[0], size);
        }
    };
}
