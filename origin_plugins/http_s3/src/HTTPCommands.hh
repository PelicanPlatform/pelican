#ifndef HTTP_COMMANDS_H
#define HTTP_COMMANDS_H


class HTTPRequest {
public:
    HTTPRequest(
        const std::string & hostUrl
    ) :
    hostUrl(hostUrl),
    requiresSignature(false),
    responseCode(0),
    includeResponseHeader(false),
    httpVerb( "POST" )
    { 
        // Parse the URL and populate
        // What to do if the function returns false?
        // TODO: Figure out best way to deal with this
        if (! parseProtocol(hostUrl, protocol)) {
            errorCode = "E_INVALID_HOST_URL";
            errorMessage = "Failed to parse protocol from host/service URL.";
        }
    }
    virtual ~HTTPRequest();

    virtual const std::string* getAccessKey() const { return nullptr; }
    virtual const std::string* getSecretKey() const { return nullptr; }

    virtual bool parseProtocol( 
        const std::string & url, 
        std::string & protocol);

    virtual bool SendHTTPRequest( const std::string & payload );

    unsigned long getResponseCode() const { return responseCode; }
    const std::string & getResultString() const { return resultString; }

protected:

    bool sendPreparedRequest(   const std::string & protocol,
                                const std::string & uri,
                                const std::string & payload );

    typedef std::map< std::string, std::string > AttributeValueMap;
    AttributeValueMap query_parameters;
    AttributeValueMap headers;

    std::string hostUrl;
    std::string protocol;

    bool requiresSignature;
    struct timespec signatureTime;

    std::string errorMessage;
    std::string errorCode;

    std::string resultString;
    unsigned long responseCode;
    unsigned long expectedResponseCode = 200;
    bool includeResponseHeader;

    std::string httpVerb;
};

class HTTPUpload : public HTTPRequest {
public:
    HTTPUpload(
        const std::string & h,
        const std::string & o
    ) :
        HTTPRequest(h),
        object(o)
    { hostUrl = hostUrl + "/" + object; }

    virtual ~HTTPUpload();

    virtual bool SendRequest( const std::string & payload, off_t offset, size_t size );

protected:
    std::string object;
    std::string path;
};

class HTTPDownload : public HTTPRequest {
public:
    HTTPDownload(
        const std::string & h,
        const std::string & o
    ) :
        HTTPRequest(h),
        object(o)
    { hostUrl = hostUrl + "/" + object; }

    virtual ~HTTPDownload();

    virtual bool SendRequest( off_t offset, size_t size );

protected:
    std::string object;
};

class HTTPHead : public HTTPRequest {
public:
    HTTPHead(
        const std::string & h,
        const std::string & o
    ) :
        HTTPRequest(h),
        object(o)
    { hostUrl = hostUrl + "/" + object; }

    virtual ~HTTPHead();

    virtual bool SendRequest();

protected:
    std::string object;
};

#endif /* HTTP_COMMANDS_H */
