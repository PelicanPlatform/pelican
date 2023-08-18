#include "XrdOuc/XrdOucEnv.hh"
#include "XrdOuc/XrdOucStream.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdVersion.hh"
#include "HTTPFileSystem.hh"
#include "HTTPDirectory.hh"
#include "HTTPFile.hh"

#include <memory>
#include <vector>
#include <stdexcept>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "stl_string_utils.hh"

HTTPFileSystem::HTTPFileSystem(XrdSysLogger *lp, const char *configfn, XrdOucEnv *envP) :
    m_env(envP),
    m_log(lp, "httpserver_")
{
    m_log.Say("------ Initializing the HTTP filesystem plugin.");
    if (!Config(lp, configfn)) {
        throw std::runtime_error("Failed to configure HTTP filesystem plugin.");
    }
}


HTTPFileSystem::~HTTPFileSystem() {
}


bool
HTTPFileSystem::handle_required_config(
    const std::string & name_from_config,
    const char * desired_name,
    const std::string & source,
    std::string & target
) {
    if( name_from_config != desired_name ) { return true; }

    if( source.empty() ) {
        std::string error;
        formatstr( error, "%s must specify a value", desired_name );
        m_log.Emsg( "Config", error.c_str() );
        return false;
    }

    // fprintf( stderr, "Setting %s = %s\n", desired_name, source.c_str() );
    target = source;
    return true;
}


bool
HTTPFileSystem::Config(XrdSysLogger *lp, const char *configfn)
{
    XrdOucEnv myEnv;
    XrdOucStream Config(&m_log, getenv("XRDINSTANCE"), &myEnv, "=====> ");

    int cfgFD = open(configfn, O_RDONLY, 0);
    if (cfgFD < 0) {
        m_log.Emsg("Config", errno, "open config file", configfn);
        return false;
    }

    char * temporary;
    std::string value;
    std::string attribute;
    Config.Attach(cfgFD);
    while ((temporary = Config.GetMyFirstWord())) {
        attribute = temporary;
        temporary = Config.GetWord();
        if(! temporary) { continue; }
        value = temporary;

        if(! handle_required_config( attribute, "httpserver.host_name",
            value, this->http_host_name ) ) { Config.Close(); return false; }
        if(! handle_required_config( attribute, "httpserver.host_url",
            value, this->http_host_url ) ) { Config.Close(); return false; }
    }

    if( this->http_host_name.empty() ) {
        m_log.Emsg("Config", "httpserver.host_name not specified");
        return false;
    }
    if( this->http_host_url.empty() ) {
        m_log.Emsg("Config", "httpserver.host_url not specified");
        return false;
    }

    int retc = Config.LastError();
    if( retc ) {
        m_log.Emsg("Config", -retc, "read config file", configfn);
        Config.Close();
        return false;
    }

    Config.Close();
    return true;
}


// Object Allocation Functions
//
XrdOssDF *
HTTPFileSystem::newDir(const char *user)
{
    return new HTTPDirectory(m_log);
}


XrdOssDF *
HTTPFileSystem::newFile(const char *user)
{
    return new HTTPFile(m_log, this);
}


int
HTTPFileSystem::Stat(const char *path, struct stat *buff,
                    int opts, XrdOucEnv *env)
{
    std::string error;

    m_log.Emsg("Stat", "Stat'ing path", path);

    HTTPFile httpFile(m_log, this);
    int rv = httpFile.Open( path, 0, (mode_t)0, *env );
    if (rv) {
        m_log.Emsg("Stat", "Failed to open path:", path);
    }
    // Assume that HTTPFile::FStat() doesn't write to buff unless it succeeds.
    rv = httpFile.Fstat( buff );
    if( rv != 0 ) {
        formatstr( error, "File %s not found.", path );
        m_log.Emsg( "Stat", error.c_str() );
        return -ENOENT;
    }

    return 0;
}

int
HTTPFileSystem::Create( const char *tid, const char *path, mode_t mode,
  XrdOucEnv &env, int opts )
{
    // Is path valid?
    std::string object;
    std::string hostname = this->getHTTPHostName();
    int rv = parse_path( hostname, path, object );
    if( rv != 0 ) { return rv; }

    return 0;
}
