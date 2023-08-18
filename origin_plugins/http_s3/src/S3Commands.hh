#ifndef S3_COMMANDS_H
#define S3_COMMANDS_H

#include "HTTPCommands.hh"

class AmazonRequest : public HTTPRequest {
public:
    AmazonRequest(
        const std::string & s,
        const std::string & akf,
        const std::string & skf,
        int sv = 4
    ) :
    HTTPRequest( s ),
    accessKeyFile(akf),
    secretKeyFile(skf),
    signatureVersion(sv)
    { 
        requiresSignature = true;
        if (! parseURL(hostUrl, host, canonicalURI)) {
            errorCode = "E_INVALID_SERVICE_URL";
            errorMessage = "Failed to parse host and canonicalURI from service URL.";
        }

        if( canonicalURI.empty() ) { canonicalURI = "/"; }

        // If we can, set the region based on the host.
        size_t secondDot = host.find( ".", 2 + 1 );
        if( host.find( "s3." ) == 0 ) {
            region = host.substr( 3, secondDot - 2 - 1 );
        }
    }
    virtual ~AmazonRequest();

    virtual const std::string* getAccessKey() const { 
        return &accessKeyFile; }
    virtual const std::string* getSecretKey() const { 
        return &secretKeyFile; }

    bool parseURL(	const std::string & url,
            std::string & host,
            std::string & path );

    virtual bool SendRequest();
    // virtual bool SendURIRequest();
    // virtual bool SendJSONRequest( const std::string & payload );
    virtual bool SendS3Request( const std::string & payload );

protected:
    bool sendV4Request( const std::string & payload, bool sendContentSHA = false );

    std::string accessKeyFile;
    std::string secretKeyFile;

    int signatureVersion;

    std::string host;
    std::string canonicalURI;

    std::string region;
    std::string service;

private:
    bool createV4Signature( const std::string & payload, std::string & authorizationHeader, bool sendContentSHA = false );

    std::string canonicalizeQueryString();
};

class AmazonS3Upload : public AmazonRequest {
    using AmazonRequest::SendRequest;
public:
    AmazonS3Upload(
        const std::string & s,
        const std::string & akf,
        const std::string & skf,
        const std::string & b,
        const std::string & o
    ) :
    AmazonRequest(s, akf, skf),
    bucket(b),
    object(o)
    {
        hostUrl = protocol + "://" + bucket + "." +
            host + canonicalURI + object;
    }

    virtual ~AmazonS3Upload();

    virtual bool SendRequest( const std::string & payload, off_t offset, size_t size );

protected:
    std::string bucket;
    std::string object;
    std::string path;
};

class AmazonS3Download : public AmazonRequest {
    using AmazonRequest::SendRequest;
public:
    AmazonS3Download(
        const std::string & s,
        const std::string & akf,
        const std::string & skf,
        const std::string & b,
        const std::string & o
    ) :
    AmazonRequest(s, akf, skf),
    bucket(b),
    object(o)
    { 
        hostUrl = protocol + "://" + bucket + "." +
            host + canonicalURI + object;
    }

    virtual ~AmazonS3Download();

    virtual bool SendRequest( off_t offset, size_t size );

protected:
    std::string bucket;
    std::string object;
};

class AmazonS3Head : public AmazonRequest {
    using AmazonRequest::SendRequest;
public:
    AmazonS3Head(
        const std::string & s,
        const std::string & akf,
        const std::string & skf,
        const std::string & b,
        const std::string & o
    ) :
    AmazonRequest(s, akf, skf),
    bucket(b),
    object(o)
    { 
        hostUrl = protocol + "://" + bucket + "." +
            host + canonicalURI + object;
    }

    virtual ~AmazonS3Head();

    virtual bool SendRequest();

protected:
    std::string bucket;
    std::string object;
};

#endif /* S3_COMMANDS_H */
