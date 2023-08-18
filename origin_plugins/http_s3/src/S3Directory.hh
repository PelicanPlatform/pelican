#pragma once

#include "HTTPDirectory.hh"


// Leaving in duplicate definitions for now. It remains
// to be seen if we'll need to change these and have specific
// behaviors for either HTTP or S3 variants in the future.

class S3Directory : public HTTPDirectory {
public:
    S3Directory(XrdSysError &log) :
        HTTPDirectory(log)
        // m_log(log)
    {
    }

    virtual ~S3Directory() {}

    virtual int
    Opendir(const char *path,
            XrdOucEnv &env) override
    {
        return -ENOSYS;
    }

    int Readdir(char *buff, int blen) override
    {
        return -ENOSYS;
    }

    int StatRet(struct stat *statStruct) override
    {
        return -ENOSYS;
    }

    int Close(long long *retsz=0) override
    {
        return -ENOSYS;
    }
};
