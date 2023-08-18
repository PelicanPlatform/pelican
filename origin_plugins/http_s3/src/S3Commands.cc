#include <sstream>
#include <algorithm>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <cassert>
#include <cstring>
#include <memory>

#include <map>
#include <string>

#include "S3Commands.hh"
#include "AWSv4-impl.hh"
#include "stl_string_utils.hh"
#include "shortfile.hh"

AmazonRequest::~AmazonRequest() { }

bool AmazonRequest::SendRequest() {
    query_parameters.insert( std::make_pair( "Version", "2012-10-01" ) );

	switch( signatureVersion ) {
		case 4:
			return sendV4Request( canonicalizeQueryString() );
		default:
			this->errorCode = "E_INTERNAL";
			this->errorMessage = "Invalid signature version.";
			// dprintf( D_ALWAYS, "Invalid signature version (%d), failing.\n", signatureVersion );
			return false;
	}
}

std::string AmazonRequest::canonicalizeQueryString() {
    return AWSv4Impl::canonicalizeQueryString( query_parameters );
}

bool AmazonRequest::parseURL(	const std::string & url,
				std::string & host,
				std::string & path ) {
    auto i = url.find( "://" );
    if( i == std::string::npos ) { return false; }
    //protocol = substring( url, 0, i );

    auto j = url.find( "/", i + 3 );
    if( j == std::string::npos ) {
        host = substring( url, i + 3 );
        path = "/";
        return true;
    }

    host = substring( url, i + 3, j );
    path = substring( url, j );
    return true;
}

void convertMessageDigestToLowercaseHex(
		const unsigned char * messageDigest,
		unsigned int mdLength,
		std::string & hexEncoded ) {
	AWSv4Impl::convertMessageDigestToLowercaseHex( messageDigest,
		mdLength, hexEncoded );
}


bool doSha256(	const std::string & payload,
				unsigned char * messageDigest,
				unsigned int * mdLength ) {
	return AWSv4Impl::doSha256( payload, messageDigest, mdLength );
}

std::string pathEncode( const std::string & original ) {
    return AWSv4Impl::pathEncode( original );
}

bool AmazonRequest::createV4Signature(	const std::string & payload,
										std::string & authorizationValue,
										bool sendContentSHA ) {
	// If we're using temporary credentials, we need to add the token
	// header here as well.  We set saKey and keyID here (well before
	// necessary) since we'll get them for free when we get the token.
	std::string keyID;
	std::string saKey;
	std::string token;
	if (!this->secretKeyFile.empty()) { // Some origins may exist in front of unauthenticated buckets
		if( ! readShortFile( this->secretKeyFile, saKey ) ) {
			this->errorCode = "E_FILE_IO";
			this->errorMessage = "Unable to read from secretkey file '" + this->secretKeyFile + "'.";
			return false;
		}
		trim( saKey );
	}
	else {
		requiresSignature = false; // If we don't create a signature, it must not be needed...
		return true; // If there was no saKey, we need not generate a signature
	}

	if (!this->accessKeyFile.empty()) { // Some origins may exist in front of unauthenticated buckets
		if( ! readShortFile( this->accessKeyFile, keyID ) ) {
			this->errorCode = "E_FILE_IO";
			this->errorMessage = "Unable to read from accesskey file '" + this->accessKeyFile + "'.";
			return false;
		}
		trim( keyID );
	}
	else {
		this->errorCode = "E_FILE_IO";
			this->errorMessage = "The secretkey file was read, but I can't read from accesskey file '" + this->secretKeyFile + "'.";
			return false;
	}
	

	time_t now; time( & now );
	struct tm brokenDownTime; gmtime_r( & now, & brokenDownTime );

	//
	// Create task 1's inputs.
	//

	// The canonical URI is the absolute path component of the service URL,
	// normalized according to RFC 3986 (removing redundant and relative
	// path components), with each path segment being URI-encoded.

	// But that sounds like a lot of work, so until something we do actually
	// requires it, I'll just assume the path is already normalized.
	canonicalURI = pathEncode( canonicalURI );

	// The canonical query string is the alphabetically sorted list of
	// URI-encoded parameter names '=' values, separated by '&'s.  That
	// wouldn't be hard to do, but we don't need to, since we send
	// everything in the POST body, instead.
	std::string canonicalQueryString;

	// This function doesn't (currently) support query parameters,
	// but no current caller attempts to use them.
	assert( (httpVerb != "GET") || query_parameters.size() == 0 );

	// The canonical headers must include the Host header, so add that
	// now if we don't have it.
	if( headers.find( "Host" ) == headers.end() ) {
		headers[ "Host" ] = host;
	}

	// S3 complains if x-amz-date isn't signed, so do this early.
	char dt[] = "YYYYMMDDThhmmssZ";
	strftime( dt, sizeof(dt), "%Y%m%dT%H%M%SZ", & brokenDownTime );
	headers[ "X-Amz-Date" ] = dt;

	char d[] = "YYYYMMDD";
	strftime( d, sizeof(d), "%Y%m%d", & brokenDownTime );

	// S3 complains if x-amz-content-sha256 isn't signed, which makes sense,
	// so do this early.

	// The canonical payload hash is the lowercase hexadecimal string of the
	// (SHA256) hash value of the payload.
	unsigned int mdLength = 0;
	unsigned char messageDigest[EVP_MAX_MD_SIZE];
	if(! doSha256( payload, messageDigest, & mdLength )) {
		this->errorCode = "E_INTERNAL";
		this->errorMessage = "Unable to hash payload.";
		// dprintf( D_ALWAYS, "Unable to hash payload, failing.\n" );
		return false;
	}
	std::string payloadHash;
	convertMessageDigestToLowercaseHex( messageDigest, mdLength, payloadHash );
	if( sendContentSHA ) {
		headers[ "x-amz-content-sha256" ] = payloadHash;
	}

	// The canonical list of headers is a sorted list of lowercase header
	// names paired via ':' with the trimmed header value, each pair
	// terminated with a newline.
	AmazonRequest::AttributeValueMap transformedHeaders;
	for( auto i = headers.begin(); i != headers.end(); ++i ) {
		std::string header = i->first;
		std::transform( header.begin(), header.end(), header.begin(), & tolower );

		std::string value = i->second;
		// We need to leave empty headers alone so that they can be used
		// to disable CURL stupidity later.
		if( value.size() == 0 ) {
			continue;
		}

		// Eliminate trailing spaces.
		unsigned j = value.length() - 1;
		while( value[j] == ' ' ) { --j; }
		if( j != value.length() - 1 ) { value.erase( j + 1 ); }

		// Eliminate leading spaces.
		for( j = 0; value[j] == ' '; ++j ) { }
		value.erase( 0, j );

		// Convert internal runs of spaces into single spaces.
		unsigned left = 1;
		unsigned right = 1;
		bool inSpaces = false;
		while( right < value.length() ) {
			if(! inSpaces) {
				if( value[right] == ' ' ) {
					inSpaces = true;
					left = right;
					++right;
				} else {
					++right;
				}
			} else {
				if( value[right] == ' ' ) {
					++right;
				} else {
					inSpaces = false;
					value.erase( left, right - left - 1 );
					right = left + 1;
				}
			}
		}

		transformedHeaders[ header ] = value;
	}

	// The canonical list of signed headers is trivial to generate while
	// generating the list of headers.
	std::string signedHeaders;
	std::string canonicalHeaders;
	for( auto i = transformedHeaders.begin(); i != transformedHeaders.end(); ++i ) {
		canonicalHeaders += i->first + ":" + i->second + "\n";
		signedHeaders += i->first + ";";
	}
	signedHeaders.erase( signedHeaders.end() - 1 );

	// Task 1: create the canonical request.
	std::string canonicalRequest = httpVerb + "\n"
								 + canonicalURI + "\n"
								 + canonicalQueryString + "\n"
								 + canonicalHeaders + "\n"
								 + signedHeaders + "\n"
								 + payloadHash;

	//
	// Create task 2's inputs.
	//

	// Hash the canonical request the way we did the payload.
	if(! doSha256( canonicalRequest, messageDigest, & mdLength )) {
		this->errorCode = "E_INTERNAL";
		this->errorMessage = "Unable to hash canonical request.";
		return false;
	}
	std::string canonicalRequestHash;
	convertMessageDigestToLowercaseHex( messageDigest, mdLength, canonicalRequestHash );

	std::string s = this->service;
	if( s.empty() ) {
		size_t i = host.find( "." );
		if( i != std::string::npos ) {
			s = host.substr( 0, i );
		} else {
			s = host;
		}
	}

	std::string r = this->region;
	if( r.empty() ) {
		size_t i = host.find( "." );
		size_t j = host.find( ".", i + 1 );
		if( j != std::string::npos ) {
			r = host.substr( i + 1, j - i - 1 );
		} else {
			r = host;
		}
	}


	// Task 2: create the string to sign.
	std::string credentialScope;
	formatstr( credentialScope, "%s/%s/%s/aws4_request", d, r.c_str(), s.c_str() );
	std::string stringToSign;
	formatstr( stringToSign, "AWS4-HMAC-SHA256\n%s\n%s\n%s",
		dt, credentialScope.c_str(), canonicalRequestHash.c_str() );

	//
	// Creating task 3's inputs was done when we checked to see if we needed
	// to get the security token, since they come along for free when we do.
	//

	// Task 3: calculate the signature.
	saKey = "AWS4" + saKey;
	const unsigned char * hmac = HMAC( EVP_sha256(), saKey.c_str(), saKey.length(),
		(unsigned char *)d, sizeof(d) - 1,
		messageDigest, & mdLength );
	if( hmac == NULL ) { return false; }

	unsigned int md2Length = 0;
	unsigned char messageDigest2[EVP_MAX_MD_SIZE];
	hmac = HMAC( EVP_sha256(), messageDigest, mdLength,
		(const unsigned char *)r.c_str(), r.length(), messageDigest2, & md2Length );
	if( hmac == NULL ) { return false; }

	hmac = HMAC( EVP_sha256(), messageDigest2, md2Length,
		(const unsigned char *)s.c_str(), s.length(), messageDigest, & mdLength );
	if( hmac == NULL ) { return false; }

	const char c[] = "aws4_request";
	hmac = HMAC( EVP_sha256(), messageDigest, mdLength,
		(const unsigned char *)c, sizeof(c) - 1, messageDigest2, & md2Length );
	if( hmac == NULL ) { return false; }

	hmac = HMAC( EVP_sha256(), messageDigest2, md2Length,
		(const unsigned char *)stringToSign.c_str(), stringToSign.length(),
		messageDigest, & mdLength );
	if( hmac == NULL ) { return false; }

	std::string signature;
	convertMessageDigestToLowercaseHex( messageDigest, mdLength, signature );

	formatstr( authorizationValue, "AWS4-HMAC-SHA256 Credential=%s/%s,"
				" SignedHeaders=%s, Signature=%s",
				keyID.c_str(), credentialScope.c_str(),
				signedHeaders.c_str(), signature.c_str() );
	return true;
}

bool AmazonRequest::sendV4Request( const std::string & payload, bool sendContentSHA ) {
    if( (protocol != "http") && (protocol != "https") ) {
        this->errorCode = "E_INVALID_SERVICE_URL";
        this->errorMessage = "Service URL not of a known protocol (http[s]).";
        return false;
    }

    if(! sendContentSHA) {
    	// dprintf( D_FULLDEBUG, "Payload is '%s'\n", payload.c_str() );
    }

    std::string authorizationValue;
    if(! createV4Signature( payload, authorizationValue, sendContentSHA )) {
        if( this->errorCode.empty() ) { this->errorCode = "E_INTERNAL"; }
        if( this->errorMessage.empty() ) { this->errorMessage = "Failed to create v4 signature."; }
        return false;
    }

	// When accessing an unauthenticated bucket, providing an auth header will cause errors
    if (!authorizationValue.empty()) {
        headers[ "Authorization" ] = authorizationValue;
    }

    return sendPreparedRequest( protocol, hostUrl, payload );
}

// It's stated in the API documentation that you can upload to any region
// via us-east-1, which is moderately crazy.
bool AmazonRequest::SendS3Request( const std::string & payload ) {
	headers[ "Content-Type" ] = "binary/octet-stream";
	std::string contentLength; formatstr( contentLength, "%zu", payload.size() );
	headers[ "Content-Length" ] = contentLength;
	// Another undocumented CURL feature: transfer-encoding is "chunked"
	// by default for "PUT", which we really don't want.
	headers[ "Transfer-Encoding" ] = "";
	service = "s3";
	if( region.empty() ) {
		region = "us-east-1";
	}
	return sendV4Request( payload, true );
}

// ---------------------------------------------------------------------------

AmazonS3Upload::~AmazonS3Upload() { }

bool AmazonS3Upload::SendRequest( const std::string & payload, off_t offset, size_t size ) {
	if( offset != 0 || size != 0 ) {
		std::string range;
		formatstr( range, "bytes=%zu-%zu", offset, offset + size - 1 );
		headers["Range"] = range.c_str();
	}

	httpVerb = "PUT";
	return SendS3Request( payload );
}

// ---------------------------------------------------------------------------

AmazonS3Download::~AmazonS3Download() { }

bool AmazonS3Download::SendRequest( off_t offset, size_t size ) {
	if( offset != 0 || size != 0 ) {
		std::string range;
		formatstr( range, "bytes=%zu-%zu", offset, offset + size );
		headers["Range"] = range.c_str();
		this->expectedResponseCode = 206;
	}

	httpVerb = "GET";
	std::string noPayloadAllowed;
	return SendS3Request( noPayloadAllowed );
}

// ---------------------------------------------------------------------------

AmazonS3Head::~AmazonS3Head() { }

bool AmazonS3Head::SendRequest() {
	httpVerb = "HEAD";
	includeResponseHeader = true;
	std::string noPayloadAllowed;
	return SendS3Request( noPayloadAllowed );
}

// ---------------------------------------------------------------------------
