// Code generated by go generate; DO NOT EDIT.
/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package param

import (
	"time"

	"github.com/spf13/viper"
)

type StringParam struct {
	name string
}

type StringSliceParam struct {
	name string
}

type BoolParam struct {
	name string
}

type IntParam struct {
	name string
}

type DurationParam struct {
	name string
}

type ObjectParam struct {
	name string
}

func GetDeprecated() map[string][]string {
    return map[string][]string{
        "Origin.EnableDirListing": []string{"Origin.EnableListings"},
        "Origin.EnableFallbackRead": []string{"Origin.EnableDirectReads"},
        "Origin.EnableWrite": []string{"Origin.EnableWrites"},
        "Origin.ExportVolume": []string{"Origin.ExportVolumes"},
        "Origin.Mode": []string{"Origin.StorageType"},
        "Origin.NamespacePrefix": []string{"Origin.FederationPrefix"},
        "Origin.S3ServiceName": []string{"none"},
        "Registry.AdminUsers": []string{"Server.UIAdminUsers"},
        "Xrootd.Port": []string{"Origin.Port", "Cache.Port"},
        "Xrootd.RunLocation": []string{"Cache.RunLocation", "Origin.RunLocation"},
    }
}

func (sP StringParam) GetString() string {
	return viper.GetString(sP.name)
}

func (sP StringParam) GetName() string {
	return sP.name
}

func (sP StringParam) IsSet() bool {
	return viper.IsSet(sP.name)
}

func (slP StringSliceParam) GetStringSlice() []string {
	return viper.GetStringSlice(slP.name)
}

func (slP StringSliceParam) IsSet() bool {
	return viper.IsSet(slP.name)
}

func (iP IntParam) GetInt() int {
	return viper.GetInt(iP.name)
}

func (iP IntParam) IsSet() bool {
	return viper.IsSet(iP.name)
}

func (bP BoolParam) GetBool() bool {
	return viper.GetBool(bP.name)
}

func (bP BoolParam) IsSet() bool {
	return viper.IsSet(bP.name)
}

func (bP DurationParam) GetDuration() time.Duration {
	return viper.GetDuration(bP.name)
}

func (bP DurationParam) IsSet() bool {
	return viper.IsSet(bP.name)
}

func (bP ObjectParam) Unmarshal(rawVal any) error {
	return viper.UnmarshalKey(bP.name, rawVal)
}

func (bP ObjectParam) IsSet() bool {
	return viper.IsSet(bP.name)
}

var (
	Cache_DataLocation = StringParam{"Cache.DataLocation"}
	Cache_ExportLocation = StringParam{"Cache.ExportLocation"}
	Cache_HighWaterMark = StringParam{"Cache.HighWaterMark"}
	Cache_LowWatermark = StringParam{"Cache.LowWatermark"}
	Cache_RunLocation = StringParam{"Cache.RunLocation"}
	Cache_Url = StringParam{"Cache.Url"}
	Cache_XRootDPrefix = StringParam{"Cache.XRootDPrefix"}
	Director_DefaultResponse = StringParam{"Director.DefaultResponse"}
	Director_GeoIPLocation = StringParam{"Director.GeoIPLocation"}
	Director_MaxMindKeyFile = StringParam{"Director.MaxMindKeyFile"}
	Director_SupportContactEmail = StringParam{"Director.SupportContactEmail"}
	Director_SupportContactUrl = StringParam{"Director.SupportContactUrl"}
	Federation_BrokerUrl = StringParam{"Federation.BrokerUrl"}
	Federation_DirectorUrl = StringParam{"Federation.DirectorUrl"}
	Federation_DiscoveryUrl = StringParam{"Federation.DiscoveryUrl"}
	Federation_JwkUrl = StringParam{"Federation.JwkUrl"}
	Federation_RegistryUrl = StringParam{"Federation.RegistryUrl"}
	Federation_TopologyNamespaceUrl = StringParam{"Federation.TopologyNamespaceUrl"}
	Federation_TopologyUrl = StringParam{"Federation.TopologyUrl"}
	IssuerKey = StringParam{"IssuerKey"}
	Issuer_AuthenticationSource = StringParam{"Issuer.AuthenticationSource"}
	Issuer_GroupFile = StringParam{"Issuer.GroupFile"}
	Issuer_GroupSource = StringParam{"Issuer.GroupSource"}
	Issuer_OIDCAuthenticationUserClaim = StringParam{"Issuer.OIDCAuthenticationUserClaim"}
	Issuer_QDLLocation = StringParam{"Issuer.QDLLocation"}
	Issuer_ScitokensServerLocation = StringParam{"Issuer.ScitokensServerLocation"}
	Issuer_TomcatLocation = StringParam{"Issuer.TomcatLocation"}
	LocalCache_DataLocation = StringParam{"LocalCache.DataLocation"}
	LocalCache_RunLocation = StringParam{"LocalCache.RunLocation"}
	LocalCache_Size = StringParam{"LocalCache.Size"}
	LocalCache_Socket = StringParam{"LocalCache.Socket"}
	Logging_Cache_Ofs = StringParam{"Logging.Cache.Ofs"}
	Logging_Cache_Pfc = StringParam{"Logging.Cache.Pfc"}
	Logging_Cache_Pss = StringParam{"Logging.Cache.Pss"}
	Logging_Cache_Scitokens = StringParam{"Logging.Cache.Scitokens"}
	Logging_Cache_Xrd = StringParam{"Logging.Cache.Xrd"}
	Logging_Cache_Xrootd = StringParam{"Logging.Cache.Xrootd"}
	Logging_Level = StringParam{"Logging.Level"}
	Logging_LogLocation = StringParam{"Logging.LogLocation"}
	Logging_Origin_Cms = StringParam{"Logging.Origin.Cms"}
	Logging_Origin_Scitokens = StringParam{"Logging.Origin.Scitokens"}
	Logging_Origin_Xrd = StringParam{"Logging.Origin.Xrd"}
	Logging_Origin_Xrootd = StringParam{"Logging.Origin.Xrootd"}
	Lotman_DbLocation = StringParam{"Lotman.DbLocation"}
	Lotman_LibLocation = StringParam{"Lotman.LibLocation"}
	Monitoring_DataLocation = StringParam{"Monitoring.DataLocation"}
	OIDC_AuthorizationEndpoint = StringParam{"OIDC.AuthorizationEndpoint"}
	OIDC_ClientID = StringParam{"OIDC.ClientID"}
	OIDC_ClientIDFile = StringParam{"OIDC.ClientIDFile"}
	OIDC_ClientRedirectHostname = StringParam{"OIDC.ClientRedirectHostname"}
	OIDC_ClientSecretFile = StringParam{"OIDC.ClientSecretFile"}
	OIDC_DeviceAuthEndpoint = StringParam{"OIDC.DeviceAuthEndpoint"}
	OIDC_Issuer = StringParam{"OIDC.Issuer"}
	OIDC_TokenEndpoint = StringParam{"OIDC.TokenEndpoint"}
	OIDC_UserInfoEndpoint = StringParam{"OIDC.UserInfoEndpoint"}
	Origin_ExportVolume = StringParam{"Origin.ExportVolume"}
	Origin_FederationPrefix = StringParam{"Origin.FederationPrefix"}
	Origin_Mode = StringParam{"Origin.Mode"}
	Origin_NamespacePrefix = StringParam{"Origin.NamespacePrefix"}
	Origin_RunLocation = StringParam{"Origin.RunLocation"}
	Origin_S3AccessKeyfile = StringParam{"Origin.S3AccessKeyfile"}
	Origin_S3Bucket = StringParam{"Origin.S3Bucket"}
	Origin_S3Region = StringParam{"Origin.S3Region"}
	Origin_S3SecretKeyfile = StringParam{"Origin.S3SecretKeyfile"}
	Origin_S3ServiceName = StringParam{"Origin.S3ServiceName"}
	Origin_S3ServiceUrl = StringParam{"Origin.S3ServiceUrl"}
	Origin_S3UrlStyle = StringParam{"Origin.S3UrlStyle"}
	Origin_ScitokensDefaultUser = StringParam{"Origin.ScitokensDefaultUser"}
	Origin_ScitokensNameMapFile = StringParam{"Origin.ScitokensNameMapFile"}
	Origin_ScitokensUsernameClaim = StringParam{"Origin.ScitokensUsernameClaim"}
	Origin_StoragePrefix = StringParam{"Origin.StoragePrefix"}
	Origin_StorageType = StringParam{"Origin.StorageType"}
	Origin_Url = StringParam{"Origin.Url"}
	Origin_XRootDPrefix = StringParam{"Origin.XRootDPrefix"}
	Plugin_Token = StringParam{"Plugin.Token"}
	Registry_DbLocation = StringParam{"Registry.DbLocation"}
	Registry_InstitutionsUrl = StringParam{"Registry.InstitutionsUrl"}
	Server_ExternalWebUrl = StringParam{"Server.ExternalWebUrl"}
	Server_Hostname = StringParam{"Server.Hostname"}
	Server_IssuerHostname = StringParam{"Server.IssuerHostname"}
	Server_IssuerJwks = StringParam{"Server.IssuerJwks"}
	Server_IssuerUrl = StringParam{"Server.IssuerUrl"}
	Server_SessionSecretFile = StringParam{"Server.SessionSecretFile"}
	Server_TLSCACertificateDirectory = StringParam{"Server.TLSCACertificateDirectory"}
	Server_TLSCACertificateFile = StringParam{"Server.TLSCACertificateFile"}
	Server_TLSCAKey = StringParam{"Server.TLSCAKey"}
	Server_TLSCertificate = StringParam{"Server.TLSCertificate"}
	Server_TLSKey = StringParam{"Server.TLSKey"}
	Server_UIActivationCodeFile = StringParam{"Server.UIActivationCodeFile"}
	Server_UIPasswordFile = StringParam{"Server.UIPasswordFile"}
	Server_WebConfigFile = StringParam{"Server.WebConfigFile"}
	Server_WebHost = StringParam{"Server.WebHost"}
	Shoveler_AMQPExchange = StringParam{"Shoveler.AMQPExchange"}
	Shoveler_AMQPTokenLocation = StringParam{"Shoveler.AMQPTokenLocation"}
	Shoveler_MessageQueueProtocol = StringParam{"Shoveler.MessageQueueProtocol"}
	Shoveler_QueueDirectory = StringParam{"Shoveler.QueueDirectory"}
	Shoveler_StompCert = StringParam{"Shoveler.StompCert"}
	Shoveler_StompCertKey = StringParam{"Shoveler.StompCertKey"}
	Shoveler_StompPassword = StringParam{"Shoveler.StompPassword"}
	Shoveler_StompUsername = StringParam{"Shoveler.StompUsername"}
	Shoveler_Topic = StringParam{"Shoveler.Topic"}
	Shoveler_URL = StringParam{"Shoveler.URL"}
	StagePlugin_MountPrefix = StringParam{"StagePlugin.MountPrefix"}
	StagePlugin_OriginPrefix = StringParam{"StagePlugin.OriginPrefix"}
	StagePlugin_ShadowOriginPrefix = StringParam{"StagePlugin.ShadowOriginPrefix"}
	Xrootd_Authfile = StringParam{"Xrootd.Authfile"}
	Xrootd_ConfigFile = StringParam{"Xrootd.ConfigFile"}
	Xrootd_DetailedMonitoringHost = StringParam{"Xrootd.DetailedMonitoringHost"}
	Xrootd_LocalMonitoringHost = StringParam{"Xrootd.LocalMonitoringHost"}
	Xrootd_MacaroonsKeyFile = StringParam{"Xrootd.MacaroonsKeyFile"}
	Xrootd_ManagerHost = StringParam{"Xrootd.ManagerHost"}
	Xrootd_Mount = StringParam{"Xrootd.Mount"}
	Xrootd_RobotsTxtFile = StringParam{"Xrootd.RobotsTxtFile"}
	Xrootd_RunLocation = StringParam{"Xrootd.RunLocation"}
	Xrootd_ScitokensConfig = StringParam{"Xrootd.ScitokensConfig"}
	Xrootd_Sitename = StringParam{"Xrootd.Sitename"}
	Xrootd_SummaryMonitoringHost = StringParam{"Xrootd.SummaryMonitoringHost"}
)

var (
	Cache_PermittedNamespaces = StringSliceParam{"Cache.PermittedNamespaces"}
	Director_CacheResponseHostnames = StringSliceParam{"Director.CacheResponseHostnames"}
	Director_FilteredServers = StringSliceParam{"Director.FilteredServers"}
	Director_OriginResponseHostnames = StringSliceParam{"Director.OriginResponseHostnames"}
	Issuer_GroupRequirements = StringSliceParam{"Issuer.GroupRequirements"}
	Monitoring_AggregatePrefixes = StringSliceParam{"Monitoring.AggregatePrefixes"}
	Origin_ExportVolumes = StringSliceParam{"Origin.ExportVolumes"}
	Origin_ScitokensRestrictedPaths = StringSliceParam{"Origin.ScitokensRestrictedPaths"}
	Registry_AdminUsers = StringSliceParam{"Registry.AdminUsers"}
	Server_Modules = StringSliceParam{"Server.Modules"}
	Server_UIAdminUsers = StringSliceParam{"Server.UIAdminUsers"}
	Shoveler_OutputDestinations = StringSliceParam{"Shoveler.OutputDestinations"}
)

var (
	Cache_Concurrency = IntParam{"Cache.Concurrency"}
	Cache_Port = IntParam{"Cache.Port"}
	Client_MaximumDownloadSpeed = IntParam{"Client.MaximumDownloadSpeed"}
	Client_MinimumDownloadSpeed = IntParam{"Client.MinimumDownloadSpeed"}
	Client_SlowTransferRampupTime = IntParam{"Client.SlowTransferRampupTime"}
	Client_SlowTransferWindow = IntParam{"Client.SlowTransferWindow"}
	Client_StoppedTransferTimeout = IntParam{"Client.StoppedTransferTimeout"}
	Client_WorkerCount = IntParam{"Client.WorkerCount"}
	Director_MaxStatResponse = IntParam{"Director.MaxStatResponse"}
	Director_MinStatResponse = IntParam{"Director.MinStatResponse"}
	Director_StatConcurrencyLimit = IntParam{"Director.StatConcurrencyLimit"}
	LocalCache_HighWaterMarkPercentage = IntParam{"LocalCache.HighWaterMarkPercentage"}
	LocalCache_LowWaterMarkPercentage = IntParam{"LocalCache.LowWaterMarkPercentage"}
	MinimumDownloadSpeed = IntParam{"MinimumDownloadSpeed"}
	Monitoring_PortHigher = IntParam{"Monitoring.PortHigher"}
	Monitoring_PortLower = IntParam{"Monitoring.PortLower"}
	Origin_Port = IntParam{"Origin.Port"}
	Server_IssuerPort = IntParam{"Server.IssuerPort"}
	Server_UILoginRateLimit = IntParam{"Server.UILoginRateLimit"}
	Server_WebPort = IntParam{"Server.WebPort"}
	Shoveler_PortHigher = IntParam{"Shoveler.PortHigher"}
	Shoveler_PortLower = IntParam{"Shoveler.PortLower"}
	Transport_MaxIdleConns = IntParam{"Transport.MaxIdleConns"}
	Xrootd_Port = IntParam{"Xrootd.Port"}
)

var (
	Cache_EnableLotman = BoolParam{"Cache.EnableLotman"}
	Cache_EnableOIDC = BoolParam{"Cache.EnableOIDC"}
	Cache_EnableVoms = BoolParam{"Cache.EnableVoms"}
	Cache_SelfTest = BoolParam{"Cache.SelfTest"}
	Client_DisableHttpProxy = BoolParam{"Client.DisableHttpProxy"}
	Client_DisableProxyFallback = BoolParam{"Client.DisableProxyFallback"}
	Debug = BoolParam{"Debug"}
	Director_EnableBroker = BoolParam{"Director.EnableBroker"}
	DisableHttpProxy = BoolParam{"DisableHttpProxy"}
	DisableProxyFallback = BoolParam{"DisableProxyFallback"}
	Logging_DisableProgressBars = BoolParam{"Logging.DisableProgressBars"}
	Lotman_EnableAPI = BoolParam{"Lotman.EnableAPI"}
	Monitoring_MetricAuthorization = BoolParam{"Monitoring.MetricAuthorization"}
	Monitoring_PromQLAuthorization = BoolParam{"Monitoring.PromQLAuthorization"}
	Origin_EnableBroker = BoolParam{"Origin.EnableBroker"}
	Origin_EnableCmsd = BoolParam{"Origin.EnableCmsd"}
	Origin_EnableDirListing = BoolParam{"Origin.EnableDirListing"}
	Origin_EnableDirectReads = BoolParam{"Origin.EnableDirectReads"}
	Origin_EnableFallbackRead = BoolParam{"Origin.EnableFallbackRead"}
	Origin_EnableIssuer = BoolParam{"Origin.EnableIssuer"}
	Origin_EnableListings = BoolParam{"Origin.EnableListings"}
	Origin_EnableOIDC = BoolParam{"Origin.EnableOIDC"}
	Origin_EnablePublicReads = BoolParam{"Origin.EnablePublicReads"}
	Origin_EnableReads = BoolParam{"Origin.EnableReads"}
	Origin_EnableUI = BoolParam{"Origin.EnableUI"}
	Origin_EnableVoms = BoolParam{"Origin.EnableVoms"}
	Origin_EnableWrite = BoolParam{"Origin.EnableWrite"}
	Origin_EnableWrites = BoolParam{"Origin.EnableWrites"}
	Origin_Multiuser = BoolParam{"Origin.Multiuser"}
	Origin_ScitokensMapSubject = BoolParam{"Origin.ScitokensMapSubject"}
	Origin_SelfTest = BoolParam{"Origin.SelfTest"}
	Registry_RequireCacheApproval = BoolParam{"Registry.RequireCacheApproval"}
	Registry_RequireKeyChaining = BoolParam{"Registry.RequireKeyChaining"}
	Registry_RequireOriginApproval = BoolParam{"Registry.RequireOriginApproval"}
	Server_EnableUI = BoolParam{"Server.EnableUI"}
	Shoveler_Enable = BoolParam{"Shoveler.Enable"}
	Shoveler_VerifyHeader = BoolParam{"Shoveler.VerifyHeader"}
	StagePlugin_Hook = BoolParam{"StagePlugin.Hook"}
	TLSSkipVerify = BoolParam{"TLSSkipVerify"}
)

var (
	Cache_SelfTestInterval = DurationParam{"Cache.SelfTestInterval"}
	Director_AdvertisementTTL = DurationParam{"Director.AdvertisementTTL"}
	Director_OriginCacheHealthTestInterval = DurationParam{"Director.OriginCacheHealthTestInterval"}
	Director_StatTimeout = DurationParam{"Director.StatTimeout"}
	Federation_TopologyReloadInterval = DurationParam{"Federation.TopologyReloadInterval"}
	Monitoring_TokenExpiresIn = DurationParam{"Monitoring.TokenExpiresIn"}
	Monitoring_TokenRefreshInterval = DurationParam{"Monitoring.TokenRefreshInterval"}
	Origin_SelfTestInterval = DurationParam{"Origin.SelfTestInterval"}
	Registry_InstitutionsUrlReloadMinutes = DurationParam{"Registry.InstitutionsUrlReloadMinutes"}
	Server_RegistrationRetryInterval = DurationParam{"Server.RegistrationRetryInterval"}
	Transport_DialerKeepAlive = DurationParam{"Transport.DialerKeepAlive"}
	Transport_DialerTimeout = DurationParam{"Transport.DialerTimeout"}
	Transport_ExpectContinueTimeout = DurationParam{"Transport.ExpectContinueTimeout"}
	Transport_IdleConnTimeout = DurationParam{"Transport.IdleConnTimeout"}
	Transport_ResponseHeaderTimeout = DurationParam{"Transport.ResponseHeaderTimeout"}
	Transport_TLSHandshakeTimeout = DurationParam{"Transport.TLSHandshakeTimeout"}
)

var (
	GeoIPOverrides = ObjectParam{"GeoIPOverrides"}
	Issuer_AuthorizationTemplates = ObjectParam{"Issuer.AuthorizationTemplates"}
	Issuer_OIDCAuthenticationRequirements = ObjectParam{"Issuer.OIDCAuthenticationRequirements"}
	Lotman_Lots = ObjectParam{"Lotman.Lots"}
	Origin_Exports = ObjectParam{"Origin.Exports"}
	Registry_CustomRegistrationFields = ObjectParam{"Registry.CustomRegistrationFields"}
	Registry_Institutions = ObjectParam{"Registry.Institutions"}
	Shoveler_IPMapping = ObjectParam{"Shoveler.IPMapping"}
)
