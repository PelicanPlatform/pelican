/**
 * Utilities for generating pre-signed URLs.
 *
 * These were originally authored by the HTCondor team under the Apache 2.0 license which
 * can also be found in the LICENSE file at the top-level directory of this project.  No
 * copyright statement was present in the original file.
 */

#include <cstring>
#include <openssl/hmac.h>

#include <map>
#include <string>
#include "AWSv4-impl.hh"

namespace AWSv4Impl {

//
// This function should not be called for anything in query_parameters,
// except for by AmazonQuery::SendRequest().
//
std::string
amazonURLEncode( const std::string & input ) {
    /*
     * See http://docs.amazonwebservices.com/AWSEC2/2010-11-15/DeveloperGuide/using-query-api.html
     *
     */
    std::string output;
    for( unsigned i = 0; i < input.length(); ++i ) {
        // "Do not URL encode ... A-Z, a-z, 0-9, hyphen ( - ),
        // underscore ( _ ), period ( . ), and tilde ( ~ ).  Percent
        // encode all other characters with %XY, where X and Y are hex
        // characters 0-9 and uppercase A-F.  Percent encode extended
        // UTF-8 characters in the form %XY%ZA..."
        if( ('A' <= input[i] && input[i] <= 'Z')
         || ('a' <= input[i] && input[i] <= 'z')
         || ('0' <= input[i] && input[i] <= '9')
         || input[i] == '-'
         || input[i] == '_'
         || input[i] == '.'
         || input[i] == '~' ) {
            char uglyHack[] = "X";
            uglyHack[0] = input[i];
            output.append( uglyHack );
        } else {
            char percentEncode[4];
            snprintf(percentEncode, 4, "%%%.2hhX", input[i]);
            output.append(percentEncode);
        }
    }

    return output;
}


std::string
pathEncode( const std::string & original ) {
	std::string segment;
	std::string encoded;
	const char * o = original.c_str();

	size_t next = 0;
	size_t offset = 0;
	size_t length = strlen( o );
	while( offset < length ) {
		next = strcspn( o + offset, "/" );
		if( next == 0 ) { encoded += "/"; offset += 1; continue; }

		segment = std::string( o + offset, next );
		encoded += amazonURLEncode( segment );

		offset += next;
	}
	return encoded;
}


void
convertMessageDigestToLowercaseHex(
  const unsigned char * messageDigest,
  unsigned int mdLength, std::string & hexEncoded ) {
	char * buffer = (char *)malloc( (mdLength * 2) + 1 );
	char * ptr = buffer;
	for (unsigned int i = 0; i < mdLength; ++i, ptr += 2) {
		sprintf(ptr, "%02x", messageDigest[i]);
	}
	hexEncoded.assign(buffer, mdLength * 2);
	free(buffer);
}

bool
doSha256( const std::string & payload,
  unsigned char * messageDigest,
  unsigned int * mdLength ) {
	EVP_MD_CTX * mdctx = EVP_MD_CTX_create();
	if( mdctx == NULL ) { return false; }

	if(! EVP_DigestInit_ex( mdctx, EVP_sha256(), NULL )) {
		EVP_MD_CTX_destroy( mdctx );
		return false;
	}

	if(! EVP_DigestUpdate( mdctx, payload.c_str(), payload.length() )) {
		EVP_MD_CTX_destroy( mdctx );
		return false;
	}

	if(! EVP_DigestFinal_ex( mdctx, messageDigest, mdLength )) {
		EVP_MD_CTX_destroy( mdctx );
		return false;
	}

	EVP_MD_CTX_destroy( mdctx );
	return true;
}

bool
createSignature( const std::string & secretAccessKey,
  const std::string & date, const std::string & region,
  const std::string & service, const std::string & stringToSign,
  std::string & signature ) {
    unsigned int mdLength = 0;
    unsigned char messageDigest[EVP_MAX_MD_SIZE];

	std::string saKey = "AWS4" + secretAccessKey;
	const unsigned char * hmac = HMAC( EVP_sha256(), saKey.c_str(), saKey.length(),
		(const unsigned char *)date.c_str(), date.length(),
		messageDigest, & mdLength );
	if( hmac == NULL ) { return false; }

	unsigned int md2Length = 0;
	unsigned char messageDigest2[EVP_MAX_MD_SIZE];
	hmac = HMAC( EVP_sha256(), messageDigest, mdLength,
		(const unsigned char *)region.c_str(), region.length(), messageDigest2, & md2Length );
	if( hmac == NULL ) { return false; }

	hmac = HMAC( EVP_sha256(), messageDigest2, md2Length,
		(const unsigned char *)service.c_str(), service.length(), messageDigest, & mdLength );
	if( hmac == NULL ) { return false; }

	const char c[] = "aws4_request";
	hmac = HMAC( EVP_sha256(), messageDigest, mdLength,
		(const unsigned char *)c, sizeof(c) - 1, messageDigest2, & md2Length );
	if( hmac == NULL ) { return false; }

	hmac = HMAC( EVP_sha256(), messageDigest2, md2Length,
		(const unsigned char *)stringToSign.c_str(), stringToSign.length(),
		messageDigest, & mdLength );
	if( hmac == NULL ) { return false; }

	convertMessageDigestToLowercaseHex( messageDigest, mdLength, signature );
	return true;
}

std::string
canonicalizeQueryString(
    const std::map< std::string, std::string > & query_parameters ) {
    std::string canonicalQueryString;
    for( auto i = query_parameters.begin(); i != query_parameters.end(); ++i ) {
        // Step 1A: The map sorts the query parameters for us.  Strictly
        // speaking, we should encode into a different AttributeValueMap
        // and then compose the string out of that, in case amazonURLEncode()
        // changes the sort order, but we don't specify parameters like that.

        // Step 1B: Encode the parameter names and values.
        std::string name = amazonURLEncode( i->first );
        std::string value = amazonURLEncode( i->second );

        // Step 1C: Separate parameter names from values with '='.
        canonicalQueryString += name + '=' + value;

        // Step 1D: Separate name-value pairs with '&';
        canonicalQueryString += '&';
    }

    // We'll always have a superflous trailing ampersand.
    canonicalQueryString.erase( canonicalQueryString.end() - 1 );
    return canonicalQueryString;
}

} /* end namespace AWSv4Impl */
