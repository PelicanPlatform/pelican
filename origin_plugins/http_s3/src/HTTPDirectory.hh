#pragma once

#include "XrdOuc/XrdOucEnv.hh"
#include "XrdOss/XrdOss.hh"


class HTTPDirectory : public XrdOssDF {
public:
    HTTPDirectory(XrdSysError &log) :
        m_log(log)
    {
    }

    virtual ~HTTPDirectory() {}

    virtual int
    Opendir(const char *path,
            XrdOucEnv &env) override
    {
        return -ENOSYS;
    }

    virtual int Readdir(char *buff, int blen)
    {
        return -ENOSYS;
    }

    virtual int StatRet(struct stat *statStruct)
    {
        return -ENOSYS;
    }

    virtual int Close(long long *retsz=0)
    {
        return -ENOSYS;
    }

protected:
    XrdSysError m_log;
};
