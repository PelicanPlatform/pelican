#include <sstream>
#include <algorithm>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <cassert>
#include <cstring>
#include <memory>
#include <filesystem>

#include <map>
#include <string>

#include "HTTPCommands.hh"
#include "stl_string_utils.hh"
#include "shortfile.hh"

//
// "This function gets called by libcurl as soon as there is data received
//  that needs to be saved. The size of the data pointed to by ptr is size
//  multiplied with nmemb, it will not be zero terminated. Return the number
//  of bytes actually taken care of. If that amount differs from the amount
//  passed to your function, it'll signal an error to the library. This will
//  abort the transfer and return CURLE_WRITE_ERROR."
//
// We also make extensive use of this function in the XML parsing code,
// for pretty much exactly the same reason.
//
size_t appendToString( const void * ptr, size_t size, size_t nmemb, void * str ) {
    if( size == 0 || nmemb == 0 ) { return 0; }

    std::string source( (const char *)ptr, size * nmemb );
    std::string * ssptr = (std::string *)str;
    ssptr->append( source );

    return (size * nmemb);
}

HTTPRequest::~HTTPRequest() { }

#define SET_CURL_SECURITY_OPTION( A, B, C ) { \
    CURLcode rv##B = curl_easy_setopt( A, B, C ); \
    if( rv##B != CURLE_OK ) { \
        this->errorCode = "E_CURL_LIB"; \
        this->errorMessage = "curl_easy_setopt( " #B " ) failed."; \
        /* dprintf( D_ALWAYS, "curl_easy_setopt( %s ) failed (%d): '%s', failing.\n", \
            #B, rv##B, curl_easy_strerror( rv##B ) ); */ \
        return false; \
    } \
}

bool HTTPRequest::parseProtocol(
        const std::string & url,
        std::string & protocol ) {

    auto i = url.find( "://" );
    if( i == std::string::npos ) { return false; }
    protocol = substring( url, 0, i );

    // This func used to parse the entire URL according
    // to the Amazon canonicalURI specs, but that functionality
    // has since been moved to the Amazon subclass. Now it just
    // grabs the protocol. Leaving the old stuff commented for
    // now, just in case...

    // auto j = url.find( "/", i + 3 );
    // if( j == std::string::npos ) {
    //     host = substring( url, i + 3 );
    //     path = "/";
    //     return true;
    // }

    // host = substring( url, i + 3, j );
    // path = substring( url, j );
    return true;
}

bool HTTPRequest::SendHTTPRequest( const std::string & payload ) {
    if( (protocol != "http") && (protocol != "https") ) {
        this->errorCode = "E_INVALID_SERVICE_URL";
        this->errorMessage = "Service URL not of a known protocol (http[s]).";
        // dprintf( D_ALWAYS, "Service URL '%s' not of a known protocol (http[s]).\n", serviceURL.c_str() );
        return false;
    }

    headers[ "Content-Type" ] = "binary/octet-stream";
    std::string contentLength; formatstr( contentLength, "%zu", payload.size() );
    headers[ "Content-Length" ] = contentLength;
    // Another undocumented CURL feature: transfer-encoding is "chunked"
    // by default for "PUT", which we really don't want.
    headers[ "Transfer-Encoding" ] = "";

	return sendPreparedRequest( protocol, hostUrl, payload );
}

int
debug_callback( CURL *, curl_infotype ci, char * data, size_t size, void * ) {
	switch( ci ) {
		default:
			break;

		case CURLINFO_TEXT:
			break;

		case CURLINFO_HEADER_IN:
			break;

		case CURLINFO_HEADER_OUT:
			break;

		case CURLINFO_DATA_IN:
			break;

		case CURLINFO_DATA_OUT:
			break;

		case CURLINFO_SSL_DATA_IN:
			break;

		case CURLINFO_SSL_DATA_OUT:
			break;
	}

	return 0;
}

size_t
read_callback( char * buffer, size_t size, size_t n, void * v ) {
	// This can be static because only one curl_easy_perform() can be
	// running at a time.
	static size_t sentSoFar = 0;
	std::string * payload = (std::string *)v;

	if( sentSoFar == payload->size() ) {
		sentSoFar = 0;
		return 0;
	}

	size_t request = size * n;
	if( request > payload->size() ) { request = payload->size(); }

	if( sentSoFar + request > payload->size() ) {
		request = payload->size() - sentSoFar;
	}

	memcpy( buffer, payload->data() + sentSoFar, request );
	sentSoFar += request;

	return request;
}

bool HTTPRequest::sendPreparedRequest(
        const std::string & protocol,
        const std::string & uri,
        const std::string & payload ) {

    CURLcode rv = curl_global_init( CURL_GLOBAL_ALL );
    if( rv != 0 ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_global_init() failed.";
        return false;
    }

    std::unique_ptr<CURL,decltype(&curl_easy_cleanup)> curl(curl_easy_init(), &curl_easy_cleanup);

    if( curl.get() == NULL ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_init() failed.";
        return false;
    }

    char errorBuffer[CURL_ERROR_SIZE];
    rv = curl_easy_setopt( curl.get(), CURLOPT_ERRORBUFFER, errorBuffer );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_ERRORBUFFER ) failed.";
        return false;
    }

    rv = curl_easy_setopt( curl.get(), CURLOPT_URL, uri.c_str() );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_URL ) failed.";
        return false;
    }

    if( httpVerb == "HEAD" ) {
        rv = curl_easy_setopt( curl.get(), CURLOPT_NOBODY, 1 );
		if( rv != CURLE_OK ) {
			this->errorCode = "E_CURL_LIB";
			this->errorMessage = "curl_easy_setopt( CURLOPT_HEAD ) failed.";
			return false;
		}
    }

	if( httpVerb == "POST" ) {
		rv = curl_easy_setopt( curl.get(), CURLOPT_POST, 1 );
		if( rv != CURLE_OK ) {
			this->errorCode = "E_CURL_LIB";
			this->errorMessage = "curl_easy_setopt( CURLOPT_POST ) failed.";
			return false;
		}

		rv = curl_easy_setopt( curl.get(), CURLOPT_POSTFIELDS, payload.c_str() );
		if( rv != CURLE_OK ) {
			this->errorCode = "E_CURL_LIB";
			this->errorMessage = "curl_easy_setopt( CURLOPT_POSTFIELDS ) failed.";
			return false;
		}
	}

	if( httpVerb == "PUT" ) {
		rv = curl_easy_setopt( curl.get(), CURLOPT_UPLOAD, 1 );
		if( rv != CURLE_OK ) {
			this->errorCode = "E_CURL_LIB";
			this->errorMessage = "curl_easy_setopt( CURLOPT_UPLOAD ) failed.";
			return false;
		}

		rv = curl_easy_setopt( curl.get(), CURLOPT_READDATA, & payload );
		if( rv != CURLE_OK ) {
			this->errorCode = "E_CURL_LIB";
			this->errorMessage = "curl_easy_setopt( CURLOPT_READDATA ) failed.";
			return false;
		}

		rv = curl_easy_setopt( curl.get(), CURLOPT_READFUNCTION, read_callback );
		if( rv != CURLE_OK ) {
			this->errorCode = "E_CURL_LIB";
			this->errorMessage = "curl_easy_setopt( CURLOPT_READFUNCTION ) failed.";
			return false;
		}
	}

    rv = curl_easy_setopt( curl.get(), CURLOPT_NOPROGRESS, 1 );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_NOPROGRESS ) failed.";
        return false;
    }

    if ( includeResponseHeader ) {
        rv = curl_easy_setopt( curl.get(), CURLOPT_HEADER, 1 );
        if( rv != CURLE_OK ) {
            this->errorCode = "E_CURL_LIB";
            this->errorMessage = "curl_easy_setopt( CURLOPT_HEADER ) failed.";
            return false;
        }
    }

    rv = curl_easy_setopt( curl.get(), CURLOPT_WRITEFUNCTION, & appendToString );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_WRITEFUNCTION ) failed.";
        return false;
    }

    rv = curl_easy_setopt( curl.get(), CURLOPT_WRITEDATA, & this->resultString );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_WRITEDATA ) failed.";
        return false;
    }

    //
    // Set security options.
    //
    SET_CURL_SECURITY_OPTION( curl.get(), CURLOPT_SSL_VERIFYPEER, 1 );
    SET_CURL_SECURITY_OPTION( curl.get(), CURLOPT_SSL_VERIFYHOST, 2 );

    // NB: Contrary to libcurl's manual, it doesn't strdup() strings passed
    // to it, so they MUST remain in scope until after we call
    // curl_easy_cleanup().  Otherwise, curl_perform() will fail with
    // a completely bogus error, number 60, claiming that there's a
    // 'problem with the SSL CA cert'.
    std::string CAFile = "";
    std::string CAPath = "";

    char * x509_ca_dir = getenv( "X509_CERT_DIR" );
    if( x509_ca_dir != NULL ) {
        CAPath = x509_ca_dir;
    }

    char * x509_ca_file = getenv( "X509_CERT_FILE" );
    if( x509_ca_file != NULL ) {
        CAFile = x509_ca_file;
    }

    if( CAPath.empty() ) {
        char * soap_ssl_ca_dir = getenv( "GAHP_SSL_CADIR" );
        if( soap_ssl_ca_dir != NULL ) {
            CAPath = soap_ssl_ca_dir;
        }
    }

    if( CAFile.empty() ) {
        char * soap_ssl_ca_file = getenv( "GAHP_SSL_CAFILE" );
        if( soap_ssl_ca_file != NULL ) {
            CAFile = soap_ssl_ca_file;
        }
    }

    if( ! CAPath.empty() ) {
        SET_CURL_SECURITY_OPTION( curl.get(), CURLOPT_CAPATH, CAPath.c_str() );
    }

    if( ! CAFile.empty() ) {
        SET_CURL_SECURITY_OPTION( curl.get(), CURLOPT_CAINFO, CAFile.c_str() );
    }

    if( setenv( "OPENSSL_ALLOW_PROXY", "1", 0 ) != 0 ) {
    }

    //
    // Configure for x.509 operation.
    //

    if( protocol == "x509" && requiresSignature ) {
        const std::string* accessKeyFilePtr = this->getAccessKey();
        const std::string* secretKeyFilePtr = this->getSecretKey();
        if (accessKeyFilePtr && secretKeyFilePtr) {

            SET_CURL_SECURITY_OPTION( curl.get(), CURLOPT_SSLKEYTYPE, "PEM" );
            SET_CURL_SECURITY_OPTION( curl.get(), CURLOPT_SSLKEY, *secretKeyFilePtr->c_str() );

            SET_CURL_SECURITY_OPTION( curl.get(), CURLOPT_SSLCERTTYPE, "PEM" );
            SET_CURL_SECURITY_OPTION( curl.get(), CURLOPT_SSLCERT, *accessKeyFilePtr->c_str() );
        }
    }

	std::string headerPair;
	struct curl_slist * header_slist = NULL;
	for( auto i = headers.begin(); i != headers.end(); ++i ) {
		formatstr( headerPair, "%s: %s", i->first.c_str(), i->second.c_str() );
		header_slist = curl_slist_append( header_slist, headerPair.c_str() );
		if( header_slist == NULL ) {
			this->errorCode = "E_CURL_LIB";
			this->errorMessage = "curl_slist_append() failed.";
			return false;
		}
	}

	rv = curl_easy_setopt( curl.get(), CURLOPT_HTTPHEADER, header_slist );
	if( rv != CURLE_OK ) {
		this->errorCode = "E_CURL_LIB";
		this->errorMessage = "curl_easy_setopt( CURLOPT_HTTPHEADER ) failed.";
		if( header_slist ) { curl_slist_free_all( header_slist ); }
		return false;
	}

retry:
    rv = curl_easy_perform( curl.get() );
    
    if( rv != 0 ) {

        this->errorCode = "E_CURL_IO";
        std::ostringstream error;
        error << "curl_easy_perform() failed (" << rv << "): '" << curl_easy_strerror( rv ) << "'.";
        this->errorMessage = error.str();
        if( header_slist ) { curl_slist_free_all( header_slist ); }

        return false;
    }

    responseCode = 0;
    rv = curl_easy_getinfo( curl.get(), CURLINFO_RESPONSE_CODE, & responseCode );
    if( rv != CURLE_OK ) {
        // So we contacted the server but it returned such gibberish that
        // CURL couldn't identify the response code.  Let's assume that's
        // bad news.  Since we're already terminally failing the request,
        // don't bother to check if this was our last chance at retrying.

        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_getinfo() failed.";
        if( header_slist ) { curl_slist_free_all( header_slist ); }

        return false;
    }

    if( responseCode == 503 && (resultString.find( "<Error><Code>RequestLimitExceeded</Code>" ) != std::string::npos) ) {
        resultString.clear();
        goto retry;
    } 

    if( header_slist ) { curl_slist_free_all( header_slist ); }

    if( responseCode != this->expectedResponseCode ) {
        formatstr( this->errorCode, "E_HTTP_RESPONSE_NOT_EXPECTED (response %lu != expected %lu)", responseCode, this->expectedResponseCode );
        this->errorMessage = resultString;
        if( this->errorMessage.empty() ) {
            formatstr( this->errorMessage, "HTTP response was %lu, not %lu, and no body was returned.", responseCode, this->expectedResponseCode );
        }
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------

HTTPUpload::~HTTPUpload() { }

bool HTTPUpload::SendRequest( const std::string & payload, off_t offset, size_t size ) {
	if( offset != 0 || size != 0 ) {
		std::string range;
		formatstr( range, "bytes=%zu-%zu", offset, offset + size - 1 );
		headers["Range"] = range.c_str();
	}

	httpVerb = "PUT";
	return SendHTTPRequest( payload );
}

// ---------------------------------------------------------------------------

HTTPDownload::~HTTPDownload() { }

bool HTTPDownload::SendRequest( off_t offset, size_t size ) {
	if( offset != 0 || size != 0 ) {
		std::string range;
		formatstr( range, "bytes=%zu-%zu", offset, offset + size - 1 );
		headers["Range"] = range.c_str();
		this->expectedResponseCode = 206;
	}

	httpVerb = "GET";
	std::string noPayloadAllowed;
	return SendHTTPRequest( noPayloadAllowed );
}

// ---------------------------------------------------------------------------

HTTPHead::~HTTPHead() { }

bool HTTPHead::SendRequest() {
	httpVerb = "HEAD";
	includeResponseHeader = true;
	std::string noPayloadAllowed;
	return SendHTTPRequest( noPayloadAllowed );
}

// ---------------------------------------------------------------------------
