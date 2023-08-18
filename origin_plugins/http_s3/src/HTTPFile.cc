#include "XrdOuc/XrdOucEnv.hh"
#include "XrdOuc/XrdOucStream.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSec/XrdSecEntityAttr.hh"
#include "XrdSfs/XrdSfsInterface.hh"
#include "XrdVersion.hh"
#include "HTTPFileSystem.hh"
#include "HTTPFile.hh"

#include <curl/curl.h>

#include <memory>
#include <mutex>
#include <sstream>
#include <vector>
#include <filesystem>

#include <map>
#include <string>
#include "HTTPCommands.hh"

#include "stl_string_utils.hh"
#include <iostream>

HTTPFileSystem* g_http_oss = nullptr;

XrdVERSIONINFO(XrdOssGetFileSystem, HTTP);

HTTPFile::HTTPFile(XrdSysError &log, HTTPFileSystem *oss) :
    m_log(log),
    m_oss(oss),
    content_length(0),
    last_modified(0)
{}

int
parse_path( const std::string & hname, const char * path, std::string & object ) {
    const std::filesystem::path p(path);
    const std::filesystem::path h(hname);

    auto prefixComponents = h.begin();
    auto pathComponents = p.begin();

    std::filesystem::path full;
    std::filesystem::path prefix;

    pathComponents++; // The path will begin with '/' while the hostname will not. Skip the first slash for comparison

    while (prefixComponents != h.end() && *prefixComponents == *pathComponents ) {
        full /= *prefixComponents++;
        prefix /= *pathComponents++;
    }

    // Check that nothing diverged before reaching end of service name
    if (prefixComponents != h.end()) {
        return -ENOENT;
    }

    std::filesystem::path obj_path;
    while (pathComponents != p.end()) {
        obj_path /= *pathComponents++;
    }

    object = obj_path.string();
    return 0;    
}


int
HTTPFile::Open(const char *path, int Oflag, mode_t Mode, XrdOucEnv &env)
{
    std::string configured_hostname = m_oss->getHTTPHostName();
    std::string configured_hostUrl = m_oss->getHTTPHostUrl();

    //
    // Check the path for validity.
    //
    std::string object;
    int rv = parse_path( configured_hostname, path, object );

    if( rv != 0 ) { return rv; }

    // We used to query S3 here to see if the object existed, but of course
    // if you're creating a file on upload, you don't care.

    this->object = object;
    //this->protocol = configured_protocol;
    this->hostname = configured_hostname;
    this->hostUrl = configured_hostUrl;

    return 0;
}


ssize_t
HTTPFile::Read(void *buffer, off_t offset, size_t size)
{
    HTTPDownload download(
        this->hostUrl,
        this->object
    );
    fprintf( stderr, "D_FULLDEBUG: about to perform download.SendRequest from HTTPFile::Read(): hostname: '%s' object: '%s'\n", hostname.c_str(), object.c_str() );

    if(! download.SendRequest( offset, size ) ) {
        fprintf( stderr, "D_FULLDEBUG: failed to send GetObject command: %lu '%s'\n", download.getResponseCode(), download.getResultString().c_str() );
        return 0;
    }

    const std::string & bytes = download.getResultString();
    memcpy( buffer, bytes.data(), bytes.size() );
    return bytes.size();
}


int
HTTPFile::Fstat(struct stat *buff)
{
    fprintf( stderr, "D_FULLDEBUG: In HTTPFile::Fstat: hostname: '%s' object: '%s'\n", hostname.c_str(), object.c_str() );
    HTTPHead head(
        this->hostUrl,
        this->object
    );

    if(! head.SendRequest()) {
        // SendRequest() returns false for all errors, including ones
        // where the server properly responded with something other
        // than code 200.  If xrootd wants us to distinguish between
        // these cases, head.getResponseCode() is initialized to 0, so
        // we can check.
        fprintf( stderr, "D_FULLDEBUG: failed to send HeadObject command: %lu '%s'\n", head.getResponseCode(), head.getResultString().c_str() );
        return -ENOENT;
    }


    std::string headers = head.getResultString();

    std::string line;
    size_t current_newline = 0;
    size_t next_newline = std::string::npos;
    size_t last_character = headers.size();
    while( current_newline != std::string::npos && current_newline != last_character - 1 ) {
        next_newline = headers.find( "\r\n", current_newline + 2);
        std::string line = substring( headers, current_newline + 2, next_newline );

        size_t colon = line.find(":");
        if( colon != std::string::npos && colon != line.size() ) {
            std::string attr = substring( line, 0, colon );
            toLower(attr); // Some servers might not follow conventional capitalization schemes
            std::string value = substring( line, colon + 1 );
            trim(value);

            if( attr == "content-length" ) {
                this->content_length = std::stol(value);
            } else if( attr == "last-modified" ) {
                struct tm t;
                char * eos = strptime( value.c_str(),
                    "%a, %d %b %Y %T %Z",
                    & t );
                if( eos == & value.c_str()[value.size()] ) {
                    time_t epoch = timegm(& t);
                    if( epoch != -1 ) {
                        this->last_modified = epoch;
                    }
                }
            }
        }

        current_newline = next_newline;
    }


    buff->st_mode = 0600 | S_IFREG;
    buff->st_nlink = 1;
    buff->st_uid = 1;
    buff->st_gid = 1;
    buff->st_size = this->content_length;
    buff->st_mtime = this->last_modified;
    buff->st_atime = 0;
    buff->st_ctime = 0;
    buff->st_dev = 0;
    buff->st_ino = 0;

    return 0;
}


ssize_t
HTTPFile::Write(const void *buffer, off_t offset, size_t size)
{
    HTTPUpload upload(
        this->hostUrl,
        this->object
    );

    std::string payload( (char *)buffer, size );
    if(! upload.SendRequest( payload, offset, size )) {
        m_log.Emsg( "Open", "upload.SendRequest() failed" );
        return -ENOENT;
    } else {
        m_log.Emsg( "Open", "upload.SendRequest() succeeded" );
        return 0;
    }
}


int HTTPFile::Close(long long *retsz)
{
    m_log.Emsg("Close", "Closed our HTTP file");
    return 0;
}


extern "C" {

/*
    This function is called when we are wrapping something.
*/
XrdOss *XrdOssAddStorageSystem2(XrdOss       *curr_oss,
                                XrdSysLogger *Logger,
                                const char   *config_fn,
                                const char   *parms,
                                XrdOucEnv    *envP)
{
    XrdSysError log(Logger, "s3_");

    log.Emsg("Initialize", "HTTP filesystem cannot be stacked with other filesystems");
    return nullptr;
}


/*
    This function is called when it is the top level file system and we are not
    wrapping anything
*/
XrdOss *XrdOssGetStorageSystem2(XrdOss       *native_oss,
                                XrdSysLogger *Logger,
                                const char   *config_fn,
                                const char   *parms,
                                XrdOucEnv    *envP)
{
    XrdSysError log(Logger, "httpserver_");

    envP->Export("XRDXROOTD_NOPOSC", "1");

    try {
        g_http_oss = new HTTPFileSystem(Logger, config_fn, envP);
        return g_http_oss;
    } catch (std::runtime_error &re) {
        log.Emsg("Initialize", "Encountered a runtime failure", re.what());
        return nullptr;
    }
}


XrdOss *XrdOssGetStorageSystem(XrdOss       *native_oss,
                               XrdSysLogger *Logger,
                               const char   *config_fn,
                               const char   *parms)
{
    return XrdOssGetStorageSystem2(native_oss, Logger, config_fn, parms, nullptr);
}


} // end extern "C"


XrdVERSIONINFO(XrdOssGetStorageSystem,  HTTPserver);
XrdVERSIONINFO(XrdOssGetStorageSystem2, HTTPserver);
XrdVERSIONINFO(XrdOssAddStorageSystem2, HTTPserver);
