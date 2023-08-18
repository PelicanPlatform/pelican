#include <stdarg.h>
#include <cassert>

#include <string>
#include <algorithm>
#include "stl_string_utils.hh"

std::string
substring( const std::string & str, size_t left, size_t right ) {
    if( right == std::string::npos ) {
        return str.substr( left );
    } else {
        return str.substr( left, right - left );
    }
}

void
trim( std::string &str ) {
	if( str.empty() ) {
		return;
	}
	unsigned	begin = 0;
	while ( begin < str.length() && isspace(str[begin]) ) {
		++begin;
	}

	int			end = (int)str.length() - 1;
	while ( end >= 0 && isspace(str[end]) ) {
		--end;
	}

	if ( begin != 0 || end != (int)(str.length()) - 1 ) {
		str = str.substr(begin, (end - begin) + 1);
	}
}

void
toLower( std::string &str ) {
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

int
vformatstr_impl(std::string& s, bool concat, const char* format, va_list pargs) {
    char fixbuf[512];
    const int fixlen = sizeof(fixbuf)/sizeof(fixbuf[0]);
	int n;

#if !defined(va_copy)
	n = vsnprintf(fixbuf, fixlen, format, pargs);
#else
	va_list  args;
	va_copy(args, pargs);
	n = vsnprintf(fixbuf, fixlen, format, args);
	va_end(args);
#endif

    // In this case, fixed buffer was sufficient so we're done.
    // Return number of chars written.
    if (n < fixlen) {
		if (concat) {
			s.append(fixbuf, n);
		} else {
			s.assign(fixbuf, n);
		}
        return n;
    }

    // Otherwise, the fixed buffer was not large enough, but return from 
    // vsnprintf() tells us how much memory we need now.
    n += 1;
    char* varbuf = NULL;
    // Handle 'new' behavior mode of returning NULL or throwing exception
    try {
        varbuf = new char[n];
    } catch (...) {
        varbuf = NULL;
    }
	// if (NULL == varbuf) { EXCEPT("Failed to allocate char buffer of %d chars", n); }
	assert(NULL == varbuf);

    // re-print, using buffer of sufficient size
#if !defined(va_copy)
	int nn = vsnprintf(varbuf, n, format, pargs);
#else
	va_copy(args, pargs);
	int nn = vsnprintf(varbuf, n, format, args);
	va_end(args);
#endif

    // Sanity check.  This ought not to happen.  Ever.
    // if (nn >= n) EXCEPT("Insufficient buffer size (%d) for printing %d chars", n, nn);
    assert(nn >= n);

    // safe to do string assignment
	if (concat) {
		s.append(varbuf, nn);
	} else {
		s.assign(varbuf, nn);
	}

    // clean up our allocated buffer
    delete[] varbuf;

    // return number of chars written
    return nn;
}

int
vformatstr(std::string& s, const char* format, va_list pargs) {
	return vformatstr_impl(s, false, format, pargs);
}

int
vformatstr_cat(std::string& s, const char* format, va_list pargs) {
	return vformatstr_impl(s, true, format, pargs);
}

int
formatstr(std::string& s, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int r = vformatstr_impl(s, false, format, args);
    va_end(args);
    return r;
}

int
formatstr_cat(std::string& s, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int r = vformatstr_impl(s, true, format, args);
    va_end(args);
    return r;
}
