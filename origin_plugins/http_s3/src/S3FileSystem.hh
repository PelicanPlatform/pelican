#pragma once

#include "XrdOuc/XrdOucStream.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdVersion.hh"
#include "XrdOss/XrdOss.hh"

#include <memory>
#include <string>

class S3FileSystem : public XrdOss {
public:

    S3FileSystem(XrdSysLogger *lp, const char *configfn, XrdOucEnv *envP);
    virtual ~S3FileSystem();

    bool
    Config(XrdSysLogger *lp, const char *configfn);

    XrdOssDF *newDir(const char *user=0);
    XrdOssDF *newFile(const char *user=0);

    int       Chmod(const char * path, mode_t mode, XrdOucEnv *env=0) {return -ENOSYS;}
    void      Connect(XrdOucEnv &env) {}
    int       Create(const char *tid, const char *path, mode_t mode,
                     XrdOucEnv &env, int opts=0);
    void      Disc(XrdOucEnv &env) {}
    void      EnvInfo(XrdOucEnv *env) {}
    uint64_t  Features() {return 0;}
    int       FSctl(int cmd, int alen, const char *args, char **resp=0) {return -ENOSYS;}
    int       Init(XrdSysLogger *lp, const char *cfn) {return 0;}
    int       Init(XrdSysLogger *lp, const char *cfn, XrdOucEnv *en) {return 0;}
    int       Mkdir(const char *path, mode_t mode, int mkpath=0,
                        XrdOucEnv  *env=0) {return -ENOSYS;}
    int       Reloc(const char *tident, const char *path,
                        const char *cgName, const char *anchor=0) {return -ENOSYS;}
    int       Remdir(const char *path, int Opts=0, XrdOucEnv *env=0) {return -ENOSYS;}
    int       Rename(const char *oPath, const char *nPath,
                         XrdOucEnv  *oEnvP=0, XrdOucEnv *nEnvP=0) {return -ENOSYS;}
    int       Stat(const char *path, struct stat *buff,
                       int opts=0, XrdOucEnv *env=0);
    int       Stats(char *buff, int blen) {return -ENOSYS;}
    int       StatFS(const char *path, char *buff, int &blen,
                         XrdOucEnv  *env=0) {return -ENOSYS;}
    int       StatLS(XrdOucEnv &env, const char *path,
                         char *buff, int &blen) {return -ENOSYS;}
    int       StatPF(const char *path, struct stat *buff, int opts) {return -ENOSYS;}
    int       StatPF(const char *path, struct stat *buff) {return -ENOSYS;}
    int       StatVS(XrdOssVSInfo *vsP, const char *sname=0, int updt=0) {return -ENOSYS;}
    int       StatXA(const char *path, char *buff, int &blen,
                         XrdOucEnv *env=0) {return -ENOSYS;}
    int       StatXP(const char *path, unsigned long long &attr,
                         XrdOucEnv  *env=0) {return -ENOSYS;}
    int       Truncate(const char *path, unsigned long long fsize,
                           XrdOucEnv *env=0) {return -ENOSYS;}
    int       Unlink(const char *path, int Opts=0, XrdOucEnv *env=0) {return -ENOSYS;}
    int       Lfn2Pfn(const char *Path, char *buff, int blen) {return -ENOSYS;}
    const char       *Lfn2Pfn(const char *Path, char *buff, int blen, int &rc) {return nullptr;}

    const std::string & getS3ServiceName() const { return s3_service_name; }
    const std::string & getS3Region() const { return s3_region; }
    const std::string & getS3ServiceURL() const { return s3_service_url; }

    const std::string & getS3AccessKeyFile() const { return s3_access_key_file; }
    const std::string & getS3SecretKeyFile() const { return s3_secret_key_file; }

private:
    XrdOucEnv *m_env;
    XrdSysError m_log;

    bool handle_required_config(
        const std::string & name_from_config,
        const char * desired_name,
        const std::string & source,
        std::string & target
    );

    std::string s3_service_name;
    std::string s3_region;
    std::string s3_service_url;

    std::string s3_access_key_file;
    std::string s3_secret_key_file;
};
