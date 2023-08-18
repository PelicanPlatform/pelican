#ifndef AWS_CREDENTIAL_H
#define AWS_CREDENTIAL_H

class AWSCredential {

    public:
        AWSCredential(
            const std::string &accessKeyID,
            const std::string &secretAccessKey,
            const std::string &securityToken
        ) :
            m_access_key(accessKeyID),
            m_secret_key(secretAccessKey),
            m_security_token(securityToken)
        {}

    private:
        const std::string m_access_key;
        const std::string m_secret_key;
        const std::string m_security_token;
};

#endif /* AWS_CREDENTIAL_H */
