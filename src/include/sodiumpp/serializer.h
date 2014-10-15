#pragma once
#include <string>
#include <type_traits>
#include <sstream>

namespace sodiumpp {
    template <typename IOStream>
    class serializer {
        IOStream& stream_;
        size_t max_item_size_;
    public:
        serializer(IOStream& stream, size_t max_item_size=10000000) : stream_(stream), max_item_size_(max_item_size) {}
        IOStream& stream() {
            return stream_;
        }
        template <typename T>
        typename std::enable_if<std::is_integral<T>::value, serializer&>::type operator<<(T x) {
            for(size_t i = 0; i < sizeof(x); ++i) {
                stream_.put((x >> ((sizeof(x)-1-i)*8)) & 0xff);
            }
            return *this;
        }
        template <typename T>
        typename std::enable_if<std::is_integral<T>::value, serializer&>::type operator>>(T& x) {
            x = 0;
            for(size_t i = 0; i < sizeof(x); ++i) {
                x |= stream_.get() << ((sizeof(x)-1-i)*8);
                if(!stream_.good()) { throw std::runtime_error("not enough bytes in stream to read item"); }
            }
            return *this;
        }
        template <typename T>
        typename std::enable_if<std::is_floating_point<T>::value, serializer&>::type operator<<(T x) {
            union {
                T x;
                char bytes[sizeof(x)];
            } convert;
            convert.x = x;
            stream_.write(&convert.bytes[0], sizeof(x));
            return *this;
        }
        template <typename T>
        typename std::enable_if<std::is_floating_point<T>::value, serializer&>::type operator>>(T& x) {
            union {
                T x;
                char bytes[sizeof(x)];
            } convert;
            stream_.read(&convert.bytes[0], sizeof(x));
            if(!stream_.good()) { throw std::runtime_error("not enough bytes in stream to read item"); }
            x = convert.x;
            return *this;
        }
        serializer& operator<<(const std::string& bytes) {
            if(bytes.size() > max_item_size_) { throw std::invalid_argument("item is larger than max_item_size"); }
            *this << bytes.size();
            stream_.write(&bytes[0], bytes.size());
            return *this;
        }
        serializer& operator>>(std::string& bytes) {
            decltype(bytes.size()) size;
            *this >> size;
            if(size > max_item_size_) { throw std::invalid_argument("item is larger than max_item_size"); }
            bytes.resize(size);
            stream_.read(&bytes[0], size);
            if(!stream_.good()) { throw std::runtime_error("not enough bytes in stream to read item"); }
            return *this;
        }
        template <typename T>
        serializer& put(T x) {
            *this << x;
            return *this;
        }
        template <typename T>
        T get() {
            T x;
            *this >> x;
            return x;
        }
    };
}
