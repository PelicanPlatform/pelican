#pragma once

#include "XrdOuc/XrdOucEnv.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSec/XrdSecEntityAttr.hh"
#include "XrdVersion.hh"
#include "XrdOss/XrdOss.hh"
#include "S3FileSystem.hh"

#include <memory>

int parse_path( const S3FileSystem & fs, const char * path, std::string & bucket, std::string & object );

class S3File : public XrdOssDF {
public:
    S3File(XrdSysError &log, S3FileSystem *oss);

    virtual ~S3File() {}

    int     Open(const char *path, int Oflag, mode_t Mode, XrdOucEnv &env) override;

    int     Fchmod(mode_t mode) override
    {
        return -ENOSYS;
    }

    void    Flush() override
    {
    }

    int     Fstat(struct stat *buf) override;

    int     Fsync() override
    {
        return -ENOSYS;
    }

    int     Fsync(XrdSfsAio *aiop) override
    {
        return -ENOSYS;
    }

    int     Ftruncate(unsigned long long size) override
    {
        return -ENOSYS;
    }

    off_t   getMmap(void **addr) override
    {
        return 0;
    }

    int     isCompressed(char *cxidp=0) override
    {
        return -ENOSYS;
    }

    ssize_t pgRead (void* buffer, off_t offset, size_t rdlen,
                        uint32_t* csvec, uint64_t opts) override
    {
        return -ENOSYS;
    }

    int     pgRead (XrdSfsAio* aioparm, uint64_t opts) override
    {
        return -ENOSYS;
    }

    ssize_t pgWrite(void* buffer, off_t offset, size_t wrlen,
                        uint32_t* csvec, uint64_t opts) override
    {
        return -ENOSYS;
    }

    int     pgWrite(XrdSfsAio* aioparm, uint64_t opts) override
    {
        return -ENOSYS;
    }

    ssize_t Read(off_t offset, size_t size) override
    {
        return -ENOSYS;
    }

    ssize_t Read(void *buffer, off_t offset, size_t size) override;

    int     Read(XrdSfsAio *aiop) override
    {
        return -ENOSYS;
    }

    ssize_t ReadRaw(void *buffer, off_t offset, size_t size) override
    {
        return -ENOSYS;
    }

    ssize_t ReadV(XrdOucIOVec *readV, int rdvcnt) override
    {
        return -ENOSYS;
    }

    ssize_t Write(const void *buffer, off_t offset, size_t size) override;

    int     Write(XrdSfsAio *aiop) override
    {
        return -ENOSYS;
    }

    ssize_t WriteV(XrdOucIOVec *writeV, int wrvcnt) override
    {
        return -ENOSYS;
    }

    int Close(long long *retsz=0);

    size_t getContentLength() { return content_length; }
    time_t getLastModified() { return last_modified; }

private:
    XrdSysError &m_log;
    S3FileSystem *m_oss;

    std::string s3_service_url;
    std::string s3_bucket_name;
    std::string s3_object_name;
    std::string s3_access_key;
    std::string s3_secret_key;

    size_t content_length;
    time_t last_modified;
};
