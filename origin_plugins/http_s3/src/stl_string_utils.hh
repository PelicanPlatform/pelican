#ifndef STL_STRING_UTILS_H
#define STL_STRING_UTILS_H

#ifndef CHECK_PRINTF_FORMAT
    #ifdef __GNUC__
        #define CHECK_PRINTF_FORMAT(a,b) __attribute__((__format__(__printf__, a, b)))
    #else
        #define CHECK_PRINTF_FORMAT(a,b)
    #endif
#endif

void trim( std::string & str );
std::string substring( const std::string & str, size_t left, size_t right = std::string::npos );
void toLower( std::string & str);

int formatstr(std::string& s, const char* format, ...) CHECK_PRINTF_FORMAT(2,3);
int formatstr_cat(std::string& s, const char* format, ...) CHECK_PRINTF_FORMAT(2,3);

#endif /* STL_STRING_UTILS_H */
