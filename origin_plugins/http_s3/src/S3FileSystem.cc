#include "XrdOuc/XrdOucEnv.hh"
#include "XrdOuc/XrdOucStream.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdVersion.hh"
#include "S3FileSystem.hh"
#include "S3Directory.hh"
#include "S3File.hh"

#include <memory>
#include <vector>
#include <stdexcept>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "stl_string_utils.hh"

S3FileSystem::S3FileSystem(XrdSysLogger *lp, const char *configfn, XrdOucEnv *envP) :
    m_env(envP),
    m_log(lp, "s3_")
{
    m_log.Say("------ Initializing the S3 filesystem plugin.");
    if (!Config(lp, configfn)) {
        throw std::runtime_error("Failed to configure S3 filesystem plugin.");
    }
}


S3FileSystem::~S3FileSystem() {
}


bool
S3FileSystem::handle_required_config(
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

    target = source;
    return true;
}


bool
S3FileSystem::Config(XrdSysLogger *lp, const char *configfn)
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

        if(! handle_required_config( attribute, "s3.service_name",
            value, this->s3_service_name ) ) { Config.Close(); return false; }
        if(! handle_required_config( attribute, "s3.region",
            value, this->s3_region ) ) { Config.Close(); return false; }
        if(! handle_required_config( attribute, "s3.service_url",
            value, this->s3_service_url ) ) { Config.Close(); return false; }
        if(! handle_required_config( attribute, "s3.access_key_file",
            value, this->s3_access_key_file ) ) { Config.Close(); return false; }
        if(! handle_required_config( attribute, "s3.secret_key_file",
            value, this->s3_secret_key_file ) ) { Config.Close(); return false; }
    }

    if( this->s3_service_name.empty() ) {
        m_log.Emsg("Config", "s3.service_name not specified");
        return false;
    }
    if( this->s3_region.empty() ) {
        m_log.Emsg("Config", "s3.region not specified");
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
S3FileSystem::newDir(const char *user)
{
    return new S3Directory(m_log);
}


XrdOssDF *
S3FileSystem::newFile(const char *user)
{
    return new S3File(m_log, this);
}


int
S3FileSystem::Stat(const char *path, struct stat *buff,
                    int opts, XrdOucEnv *env)
{
    std::string error;

    m_log.Emsg("Stat", "Stat'ing path", path);

    S3File s3file(m_log, this);
    int rv = s3file.Open( path, 0, (mode_t)0, *env );
    if (rv) {
        m_log.Emsg("Stat", "Failed to open path:", path);
    }
    // Assume that S3File::FStat() doesn't write to buff unless it succeeds.
    rv = s3file.Fstat( buff );
    if( rv != 0 ) {
        formatstr( error, "File %s not found.", path );
        m_log.Emsg( "Stat", error.c_str() );
        return -ENOENT;
    }

    return 0;
}

int
S3FileSystem::Create( const char *tid, const char *path, mode_t mode,
  XrdOucEnv &env, int opts )
{
    // Is path valid?
    std::string bucket, object;
    int rv = parse_path( * this, path, bucket, object );
    if( rv != 0 ) { return rv; }

    //
    // We could instead invoke the upload mchinery directly to create a
    // 0-byte file, but it seems smarter to remove a round-trip (in
    // S3File::Open(), checking if the file exists) than to add one
    // (here, creating the file if it doesn't exist).
    //

    return 0;
}
