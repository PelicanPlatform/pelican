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
)

type Config struct {
	Cache struct {
		BlocksToPrefetch int `mapstructure:"blockstoprefetch" yaml:"BlocksToPrefetch"`
		Concurrency int `mapstructure:"concurrency" yaml:"Concurrency"`
		DataLocation string `mapstructure:"datalocation" yaml:"DataLocation"`
		DataLocations []string `mapstructure:"datalocations" yaml:"DataLocations"`
		DefaultCacheTimeout time.Duration `mapstructure:"defaultcachetimeout" yaml:"DefaultCacheTimeout"`
		EnableLotman bool `mapstructure:"enablelotman" yaml:"EnableLotman"`
		EnableOIDC bool `mapstructure:"enableoidc" yaml:"EnableOIDC"`
		EnableVoms bool `mapstructure:"enablevoms" yaml:"EnableVoms"`
		ExportLocation string `mapstructure:"exportlocation" yaml:"ExportLocation"`
		HighWaterMark string `mapstructure:"highwatermark" yaml:"HighWaterMark"`
		LocalRoot string `mapstructure:"localroot" yaml:"LocalRoot"`
		LowWatermark string `mapstructure:"lowwatermark" yaml:"LowWatermark"`
		MetaLocations []string `mapstructure:"metalocations" yaml:"MetaLocations"`
		NamespaceLocation string `mapstructure:"namespacelocation" yaml:"NamespaceLocation"`
		PermittedNamespaces []string `mapstructure:"permittednamespaces" yaml:"PermittedNamespaces"`
		Port int `mapstructure:"port" yaml:"Port"`
		RunLocation string `mapstructure:"runlocation" yaml:"RunLocation"`
		SelfTest bool `mapstructure:"selftest" yaml:"SelfTest"`
		SelfTestInterval time.Duration `mapstructure:"selftestinterval" yaml:"SelfTestInterval"`
		SentinelLocation string `mapstructure:"sentinellocation" yaml:"SentinelLocation"`
		StorageLocation string `mapstructure:"storagelocation" yaml:"StorageLocation"`
		Url string `mapstructure:"url" yaml:"Url"`
		XRootDPrefix string `mapstructure:"xrootdprefix" yaml:"XRootDPrefix"`
	} `mapstructure:"cache" yaml:"Cache"`
	Client struct {
		DisableHttpProxy bool `mapstructure:"disablehttpproxy" yaml:"DisableHttpProxy"`
		DisableProxyFallback bool `mapstructure:"disableproxyfallback" yaml:"DisableProxyFallback"`
		MaximumDownloadSpeed int `mapstructure:"maximumdownloadspeed" yaml:"MaximumDownloadSpeed"`
		MinimumDownloadSpeed int `mapstructure:"minimumdownloadspeed" yaml:"MinimumDownloadSpeed"`
		SlowTransferRampupTime time.Duration `mapstructure:"slowtransferrampuptime" yaml:"SlowTransferRampupTime"`
		SlowTransferWindow time.Duration `mapstructure:"slowtransferwindow" yaml:"SlowTransferWindow"`
		StoppedTransferTimeout time.Duration `mapstructure:"stoppedtransfertimeout" yaml:"StoppedTransferTimeout"`
		WorkerCount int `mapstructure:"workercount" yaml:"WorkerCount"`
	} `mapstructure:"client" yaml:"Client"`
	ConfigDir string `mapstructure:"configdir" yaml:"ConfigDir"`
	ConfigLocations []string `mapstructure:"configlocations" yaml:"ConfigLocations"`
	Debug bool `mapstructure:"debug" yaml:"Debug"`
	Director struct {
		AdvertisementTTL time.Duration `mapstructure:"advertisementttl" yaml:"AdvertisementTTL"`
		AssumePresenceAtSingleOrigin bool `mapstructure:"assumepresenceatsingleorigin" yaml:"AssumePresenceAtSingleOrigin"`
		CachePresenceCapacity int `mapstructure:"cachepresencecapacity" yaml:"CachePresenceCapacity"`
		CachePresenceTTL time.Duration `mapstructure:"cachepresencettl" yaml:"CachePresenceTTL"`
		CacheResponseHostnames []string `mapstructure:"cacheresponsehostnames" yaml:"CacheResponseHostnames"`
		CacheSortMethod string `mapstructure:"cachesortmethod" yaml:"CacheSortMethod"`
		CachesPullFromCaches bool `mapstructure:"cachespullfromcaches" yaml:"CachesPullFromCaches"`
		CheckCachePresence bool `mapstructure:"checkcachepresence" yaml:"CheckCachePresence"`
		CheckOriginPresence bool `mapstructure:"checkoriginpresence" yaml:"CheckOriginPresence"`
		DbLocation string `mapstructure:"dblocation" yaml:"DbLocation"`
		DefaultResponse string `mapstructure:"defaultresponse" yaml:"DefaultResponse"`
		EnableBroker bool `mapstructure:"enablebroker" yaml:"EnableBroker"`
		EnableOIDC bool `mapstructure:"enableoidc" yaml:"EnableOIDC"`
		EnableStat bool `mapstructure:"enablestat" yaml:"EnableStat"`
		FilteredServers []string `mapstructure:"filteredservers" yaml:"FilteredServers"`
		GeoIPLocation string `mapstructure:"geoiplocation" yaml:"GeoIPLocation"`
		MaxMindKeyFile string `mapstructure:"maxmindkeyfile" yaml:"MaxMindKeyFile"`
		MaxStatResponse int `mapstructure:"maxstatresponse" yaml:"MaxStatResponse"`
		MinStatResponse int `mapstructure:"minstatresponse" yaml:"MinStatResponse"`
		OriginCacheHealthTestInterval time.Duration `mapstructure:"origincachehealthtestinterval" yaml:"OriginCacheHealthTestInterval"`
		OriginResponseHostnames []string `mapstructure:"originresponsehostnames" yaml:"OriginResponseHostnames"`
		StatConcurrencyLimit int `mapstructure:"statconcurrencylimit" yaml:"StatConcurrencyLimit"`
		StatTimeout time.Duration `mapstructure:"stattimeout" yaml:"StatTimeout"`
		SupportContactEmail string `mapstructure:"supportcontactemail" yaml:"SupportContactEmail"`
		SupportContactUrl string `mapstructure:"supportcontacturl" yaml:"SupportContactUrl"`
		X509ClientAuthenticationPrefixes []string `mapstructure:"x509clientauthenticationprefixes" yaml:"X509ClientAuthenticationPrefixes"`
	} `mapstructure:"director" yaml:"Director"`
	DisableHttpProxy bool `mapstructure:"disablehttpproxy" yaml:"DisableHttpProxy"`
	DisableProxyFallback bool `mapstructure:"disableproxyfallback" yaml:"DisableProxyFallback"`
	Federation struct {
		BrokerUrl string `mapstructure:"brokerurl" yaml:"BrokerUrl"`
		DirectorUrl string `mapstructure:"directorurl" yaml:"DirectorUrl"`
		DiscoveryUrl string `mapstructure:"discoveryurl" yaml:"DiscoveryUrl"`
		JwkUrl string `mapstructure:"jwkurl" yaml:"JwkUrl"`
		RegistryUrl string `mapstructure:"registryurl" yaml:"RegistryUrl"`
		TopologyDowntimeUrl string `mapstructure:"topologydowntimeurl" yaml:"TopologyDowntimeUrl"`
		TopologyNamespaceUrl string `mapstructure:"topologynamespaceurl" yaml:"TopologyNamespaceUrl"`
		TopologyReloadInterval time.Duration `mapstructure:"topologyreloadinterval" yaml:"TopologyReloadInterval"`
		TopologyUrl string `mapstructure:"topologyurl" yaml:"TopologyUrl"`
	} `mapstructure:"federation" yaml:"Federation"`
	GeoIPOverrides interface{} `mapstructure:"geoipoverrides" yaml:"GeoIPOverrides"`
	Issuer struct {
		AuthenticationSource string `mapstructure:"authenticationsource" yaml:"AuthenticationSource"`
		AuthorizationTemplates interface{} `mapstructure:"authorizationtemplates" yaml:"AuthorizationTemplates"`
		GroupFile string `mapstructure:"groupfile" yaml:"GroupFile"`
		GroupRequirements []string `mapstructure:"grouprequirements" yaml:"GroupRequirements"`
		GroupSource string `mapstructure:"groupsource" yaml:"GroupSource"`
		IssuerClaimValue string `mapstructure:"issuerclaimvalue" yaml:"IssuerClaimValue"`
		OIDCAuthenticationRequirements interface{} `mapstructure:"oidcauthenticationrequirements" yaml:"OIDCAuthenticationRequirements"`
		OIDCAuthenticationUserClaim string `mapstructure:"oidcauthenticationuserclaim" yaml:"OIDCAuthenticationUserClaim"`
		OIDCGroupClaim string `mapstructure:"oidcgroupclaim" yaml:"OIDCGroupClaim"`
		QDLLocation string `mapstructure:"qdllocation" yaml:"QDLLocation"`
		ScitokensServerLocation string `mapstructure:"scitokensserverlocation" yaml:"ScitokensServerLocation"`
		TomcatLocation string `mapstructure:"tomcatlocation" yaml:"TomcatLocation"`
		UserStripDomain bool `mapstructure:"userstripdomain" yaml:"UserStripDomain"`
	} `mapstructure:"issuer" yaml:"Issuer"`
	IssuerKey string `mapstructure:"issuerkey" yaml:"IssuerKey"`
	LocalCache struct {
		DataLocation string `mapstructure:"datalocation" yaml:"DataLocation"`
		HighWaterMarkPercentage int `mapstructure:"highwatermarkpercentage" yaml:"HighWaterMarkPercentage"`
		LowWaterMarkPercentage int `mapstructure:"lowwatermarkpercentage" yaml:"LowWaterMarkPercentage"`
		RunLocation string `mapstructure:"runlocation" yaml:"RunLocation"`
		Size string `mapstructure:"size" yaml:"Size"`
		Socket string `mapstructure:"socket" yaml:"Socket"`
	} `mapstructure:"localcache" yaml:"LocalCache"`
	Logging struct {
		Cache struct {
			Http string `mapstructure:"http" yaml:"Http"`
			Ofs string `mapstructure:"ofs" yaml:"Ofs"`
			Pfc string `mapstructure:"pfc" yaml:"Pfc"`
			Pss string `mapstructure:"pss" yaml:"Pss"`
			Scitokens string `mapstructure:"scitokens" yaml:"Scitokens"`
			Xrd string `mapstructure:"xrd" yaml:"Xrd"`
			Xrootd string `mapstructure:"xrootd" yaml:"Xrootd"`
		} `mapstructure:"cache" yaml:"Cache"`
		DisableProgressBars bool `mapstructure:"disableprogressbars" yaml:"DisableProgressBars"`
		Level string `mapstructure:"level" yaml:"Level"`
		LogLocation string `mapstructure:"loglocation" yaml:"LogLocation"`
		Origin struct {
			Cms string `mapstructure:"cms" yaml:"Cms"`
			Http string `mapstructure:"http" yaml:"Http"`
			Ofs string `mapstructure:"ofs" yaml:"Ofs"`
			Oss string `mapstructure:"oss" yaml:"Oss"`
			Scitokens string `mapstructure:"scitokens" yaml:"Scitokens"`
			Xrd string `mapstructure:"xrd" yaml:"Xrd"`
			Xrootd string `mapstructure:"xrootd" yaml:"Xrootd"`
		} `mapstructure:"origin" yaml:"Origin"`
	} `mapstructure:"logging" yaml:"Logging"`
	Lotman struct {
		DbLocation string `mapstructure:"dblocation" yaml:"DbLocation"`
		EnableAPI bool `mapstructure:"enableapi" yaml:"EnableAPI"`
		LibLocation string `mapstructure:"liblocation" yaml:"LibLocation"`
		Lots interface{} `mapstructure:"lots" yaml:"Lots"`
	} `mapstructure:"lotman" yaml:"Lotman"`
	MinimumDownloadSpeed int `mapstructure:"minimumdownloadspeed" yaml:"MinimumDownloadSpeed"`
	Monitoring struct {
		AggregatePrefixes []string `mapstructure:"aggregateprefixes" yaml:"AggregatePrefixes"`
		DataLocation string `mapstructure:"datalocation" yaml:"DataLocation"`
		DataRetention time.Duration `mapstructure:"dataretention" yaml:"DataRetention"`
		MetricAuthorization bool `mapstructure:"metricauthorization" yaml:"MetricAuthorization"`
		PortHigher int `mapstructure:"porthigher" yaml:"PortHigher"`
		PortLower int `mapstructure:"portlower" yaml:"PortLower"`
		PromQLAuthorization bool `mapstructure:"promqlauthorization" yaml:"PromQLAuthorization"`
		TokenExpiresIn time.Duration `mapstructure:"tokenexpiresin" yaml:"TokenExpiresIn"`
		TokenRefreshInterval time.Duration `mapstructure:"tokenrefreshinterval" yaml:"TokenRefreshInterval"`
	} `mapstructure:"monitoring" yaml:"Monitoring"`
	OIDC struct {
		AuthorizationEndpoint string `mapstructure:"authorizationendpoint" yaml:"AuthorizationEndpoint"`
		ClientID string `mapstructure:"clientid" yaml:"ClientID"`
		ClientIDFile string `mapstructure:"clientidfile" yaml:"ClientIDFile"`
		ClientRedirectHostname string `mapstructure:"clientredirecthostname" yaml:"ClientRedirectHostname"`
		ClientSecretFile string `mapstructure:"clientsecretfile" yaml:"ClientSecretFile"`
		DeviceAuthEndpoint string `mapstructure:"deviceauthendpoint" yaml:"DeviceAuthEndpoint"`
		Issuer string `mapstructure:"issuer" yaml:"Issuer"`
		TokenEndpoint string `mapstructure:"tokenendpoint" yaml:"TokenEndpoint"`
		UserInfoEndpoint string `mapstructure:"userinfoendpoint" yaml:"UserInfoEndpoint"`
	} `mapstructure:"oidc" yaml:"OIDC"`
	Origin struct {
		DbLocation string `mapstructure:"dblocation" yaml:"DbLocation"`
		DirectorTest bool `mapstructure:"directortest" yaml:"DirectorTest"`
		EnableBroker bool `mapstructure:"enablebroker" yaml:"EnableBroker"`
		EnableCmsd bool `mapstructure:"enablecmsd" yaml:"EnableCmsd"`
		EnableDirListing bool `mapstructure:"enabledirlisting" yaml:"EnableDirListing"`
		EnableDirectReads bool `mapstructure:"enabledirectreads" yaml:"EnableDirectReads"`
		EnableFallbackRead bool `mapstructure:"enablefallbackread" yaml:"EnableFallbackRead"`
		EnableIssuer bool `mapstructure:"enableissuer" yaml:"EnableIssuer"`
		EnableListings bool `mapstructure:"enablelistings" yaml:"EnableListings"`
		EnableMacaroons bool `mapstructure:"enablemacaroons" yaml:"EnableMacaroons"`
		EnableOIDC bool `mapstructure:"enableoidc" yaml:"EnableOIDC"`
		EnablePublicReads bool `mapstructure:"enablepublicreads" yaml:"EnablePublicReads"`
		EnableReads bool `mapstructure:"enablereads" yaml:"EnableReads"`
		EnableUI bool `mapstructure:"enableui" yaml:"EnableUI"`
		EnableVoms bool `mapstructure:"enablevoms" yaml:"EnableVoms"`
		EnableWrite bool `mapstructure:"enablewrite" yaml:"EnableWrite"`
		EnableWrites bool `mapstructure:"enablewrites" yaml:"EnableWrites"`
		ExportVolume string `mapstructure:"exportvolume" yaml:"ExportVolume"`
		ExportVolumes []string `mapstructure:"exportvolumes" yaml:"ExportVolumes"`
		Exports interface{} `mapstructure:"exports" yaml:"Exports"`
		FederationPrefix string `mapstructure:"federationprefix" yaml:"FederationPrefix"`
		GlobusClientIDFile string `mapstructure:"globusclientidfile" yaml:"GlobusClientIDFile"`
		GlobusClientSecretFile string `mapstructure:"globusclientsecretfile" yaml:"GlobusClientSecretFile"`
		GlobusCollectionID string `mapstructure:"globuscollectionid" yaml:"GlobusCollectionID"`
		GlobusCollectionName string `mapstructure:"globuscollectionname" yaml:"GlobusCollectionName"`
		GlobusConfigLocation string `mapstructure:"globusconfiglocation" yaml:"GlobusConfigLocation"`
		HttpAuthTokenFile string `mapstructure:"httpauthtokenfile" yaml:"HttpAuthTokenFile"`
		HttpServiceUrl string `mapstructure:"httpserviceurl" yaml:"HttpServiceUrl"`
		Mode string `mapstructure:"mode" yaml:"Mode"`
		Multiuser bool `mapstructure:"multiuser" yaml:"Multiuser"`
		NamespacePrefix string `mapstructure:"namespaceprefix" yaml:"NamespacePrefix"`
		Port int `mapstructure:"port" yaml:"Port"`
		RunLocation string `mapstructure:"runlocation" yaml:"RunLocation"`
		S3AccessKeyfile string `mapstructure:"s3accesskeyfile" yaml:"S3AccessKeyfile"`
		S3Bucket string `mapstructure:"s3bucket" yaml:"S3Bucket"`
		S3Region string `mapstructure:"s3region" yaml:"S3Region"`
		S3SecretKeyfile string `mapstructure:"s3secretkeyfile" yaml:"S3SecretKeyfile"`
		S3ServiceName string `mapstructure:"s3servicename" yaml:"S3ServiceName"`
		S3ServiceUrl string `mapstructure:"s3serviceurl" yaml:"S3ServiceUrl"`
		S3UrlStyle string `mapstructure:"s3urlstyle" yaml:"S3UrlStyle"`
		ScitokensDefaultUser string `mapstructure:"scitokensdefaultuser" yaml:"ScitokensDefaultUser"`
		ScitokensMapSubject bool `mapstructure:"scitokensmapsubject" yaml:"ScitokensMapSubject"`
		ScitokensNameMapFile string `mapstructure:"scitokensnamemapfile" yaml:"ScitokensNameMapFile"`
		ScitokensRestrictedPaths []string `mapstructure:"scitokensrestrictedpaths" yaml:"ScitokensRestrictedPaths"`
		ScitokensUsernameClaim string `mapstructure:"scitokensusernameclaim" yaml:"ScitokensUsernameClaim"`
		SelfTest bool `mapstructure:"selftest" yaml:"SelfTest"`
		SelfTestInterval time.Duration `mapstructure:"selftestinterval" yaml:"SelfTestInterval"`
		StoragePrefix string `mapstructure:"storageprefix" yaml:"StoragePrefix"`
		StorageType string `mapstructure:"storagetype" yaml:"StorageType"`
		Url string `mapstructure:"url" yaml:"Url"`
		XRootDPrefix string `mapstructure:"xrootdprefix" yaml:"XRootDPrefix"`
		XRootServiceUrl string `mapstructure:"xrootserviceurl" yaml:"XRootServiceUrl"`
	} `mapstructure:"origin" yaml:"Origin"`
	Plugin struct {
		Token string `mapstructure:"token" yaml:"Token"`
	} `mapstructure:"plugin" yaml:"Plugin"`
	Registry struct {
		AdminUsers []string `mapstructure:"adminusers" yaml:"AdminUsers"`
		CustomRegistrationFields interface{} `mapstructure:"customregistrationfields" yaml:"CustomRegistrationFields"`
		DbLocation string `mapstructure:"dblocation" yaml:"DbLocation"`
		Institutions interface{} `mapstructure:"institutions" yaml:"Institutions"`
		InstitutionsUrl string `mapstructure:"institutionsurl" yaml:"InstitutionsUrl"`
		InstitutionsUrlReloadMinutes time.Duration `mapstructure:"institutionsurlreloadminutes" yaml:"InstitutionsUrlReloadMinutes"`
		RequireCacheApproval bool `mapstructure:"requirecacheapproval" yaml:"RequireCacheApproval"`
		RequireKeyChaining bool `mapstructure:"requirekeychaining" yaml:"RequireKeyChaining"`
		RequireOriginApproval bool `mapstructure:"requireoriginapproval" yaml:"RequireOriginApproval"`
	} `mapstructure:"registry" yaml:"Registry"`
	Server struct {
		EnablePprof bool `mapstructure:"enablepprof" yaml:"EnablePprof"`
		EnableUI bool `mapstructure:"enableui" yaml:"EnableUI"`
		ExternalWebUrl string `mapstructure:"externalweburl" yaml:"ExternalWebUrl"`
		Hostname string `mapstructure:"hostname" yaml:"Hostname"`
		IssuerHostname string `mapstructure:"issuerhostname" yaml:"IssuerHostname"`
		IssuerJwks string `mapstructure:"issuerjwks" yaml:"IssuerJwks"`
		IssuerPort int `mapstructure:"issuerport" yaml:"IssuerPort"`
		IssuerUrl string `mapstructure:"issuerurl" yaml:"IssuerUrl"`
		Modules []string `mapstructure:"modules" yaml:"Modules"`
		RegistrationRetryInterval time.Duration `mapstructure:"registrationretryinterval" yaml:"RegistrationRetryInterval"`
		SessionSecretFile string `mapstructure:"sessionsecretfile" yaml:"SessionSecretFile"`
		StartupTimeout time.Duration `mapstructure:"startuptimeout" yaml:"StartupTimeout"`
		TLSCACertificateDirectory string `mapstructure:"tlscacertificatedirectory" yaml:"TLSCACertificateDirectory"`
		TLSCACertificateFile string `mapstructure:"tlscacertificatefile" yaml:"TLSCACertificateFile"`
		TLSCAKey string `mapstructure:"tlscakey" yaml:"TLSCAKey"`
		TLSCertificate string `mapstructure:"tlscertificate" yaml:"TLSCertificate"`
		TLSKey string `mapstructure:"tlskey" yaml:"TLSKey"`
		UIActivationCodeFile string `mapstructure:"uiactivationcodefile" yaml:"UIActivationCodeFile"`
		UIAdminUsers []string `mapstructure:"uiadminusers" yaml:"UIAdminUsers"`
		UILoginRateLimit int `mapstructure:"uiloginratelimit" yaml:"UILoginRateLimit"`
		UIPasswordFile string `mapstructure:"uipasswordfile" yaml:"UIPasswordFile"`
		WebConfigFile string `mapstructure:"webconfigfile" yaml:"WebConfigFile"`
		WebHost string `mapstructure:"webhost" yaml:"WebHost"`
		WebPort int `mapstructure:"webport" yaml:"WebPort"`
	} `mapstructure:"server" yaml:"Server"`
	Shoveler struct {
		AMQPExchange string `mapstructure:"amqpexchange" yaml:"AMQPExchange"`
		AMQPTokenLocation string `mapstructure:"amqptokenlocation" yaml:"AMQPTokenLocation"`
		Enable bool `mapstructure:"enable" yaml:"Enable"`
		IPMapping interface{} `mapstructure:"ipmapping" yaml:"IPMapping"`
		MessageQueueProtocol string `mapstructure:"messagequeueprotocol" yaml:"MessageQueueProtocol"`
		OutputDestinations []string `mapstructure:"outputdestinations" yaml:"OutputDestinations"`
		PortHigher int `mapstructure:"porthigher" yaml:"PortHigher"`
		PortLower int `mapstructure:"portlower" yaml:"PortLower"`
		QueueDirectory string `mapstructure:"queuedirectory" yaml:"QueueDirectory"`
		StompCert string `mapstructure:"stompcert" yaml:"StompCert"`
		StompCertKey string `mapstructure:"stompcertkey" yaml:"StompCertKey"`
		StompPassword string `mapstructure:"stomppassword" yaml:"StompPassword"`
		StompUsername string `mapstructure:"stompusername" yaml:"StompUsername"`
		Topic string `mapstructure:"topic" yaml:"Topic"`
		URL string `mapstructure:"url" yaml:"URL"`
		VerifyHeader bool `mapstructure:"verifyheader" yaml:"VerifyHeader"`
	} `mapstructure:"shoveler" yaml:"Shoveler"`
	StagePlugin struct {
		Hook bool `mapstructure:"hook" yaml:"Hook"`
		MountPrefix string `mapstructure:"mountprefix" yaml:"MountPrefix"`
		OriginPrefix string `mapstructure:"originprefix" yaml:"OriginPrefix"`
		ShadowOriginPrefix string `mapstructure:"shadoworiginprefix" yaml:"ShadowOriginPrefix"`
	} `mapstructure:"stageplugin" yaml:"StagePlugin"`
	TLSSkipVerify bool `mapstructure:"tlsskipverify" yaml:"TLSSkipVerify"`
	Transport struct {
		DialerKeepAlive time.Duration `mapstructure:"dialerkeepalive" yaml:"DialerKeepAlive"`
		DialerTimeout time.Duration `mapstructure:"dialertimeout" yaml:"DialerTimeout"`
		ExpectContinueTimeout time.Duration `mapstructure:"expectcontinuetimeout" yaml:"ExpectContinueTimeout"`
		IdleConnTimeout time.Duration `mapstructure:"idleconntimeout" yaml:"IdleConnTimeout"`
		MaxIdleConns int `mapstructure:"maxidleconns" yaml:"MaxIdleConns"`
		ResponseHeaderTimeout time.Duration `mapstructure:"responseheadertimeout" yaml:"ResponseHeaderTimeout"`
		TLSHandshakeTimeout time.Duration `mapstructure:"tlshandshaketimeout" yaml:"TLSHandshakeTimeout"`
	} `mapstructure:"transport" yaml:"Transport"`
	Xrootd struct {
		AuthRefreshInterval time.Duration `mapstructure:"authrefreshinterval" yaml:"AuthRefreshInterval"`
		Authfile string `mapstructure:"authfile" yaml:"Authfile"`
		ConfigFile string `mapstructure:"configfile" yaml:"ConfigFile"`
		DetailedMonitoringHost string `mapstructure:"detailedmonitoringhost" yaml:"DetailedMonitoringHost"`
		DetailedMonitoringPort int `mapstructure:"detailedmonitoringport" yaml:"DetailedMonitoringPort"`
		LocalMonitoringHost string `mapstructure:"localmonitoringhost" yaml:"LocalMonitoringHost"`
		MacaroonsKeyFile string `mapstructure:"macaroonskeyfile" yaml:"MacaroonsKeyFile"`
		ManagerHost string `mapstructure:"managerhost" yaml:"ManagerHost"`
		ManagerPort int `mapstructure:"managerport" yaml:"ManagerPort"`
		MaxStartupWait time.Duration `mapstructure:"maxstartupwait" yaml:"MaxStartupWait"`
		Mount string `mapstructure:"mount" yaml:"Mount"`
		Port int `mapstructure:"port" yaml:"Port"`
		RobotsTxtFile string `mapstructure:"robotstxtfile" yaml:"RobotsTxtFile"`
		RunLocation string `mapstructure:"runlocation" yaml:"RunLocation"`
		ScitokensConfig string `mapstructure:"scitokensconfig" yaml:"ScitokensConfig"`
		Sitename string `mapstructure:"sitename" yaml:"Sitename"`
		SummaryMonitoringHost string `mapstructure:"summarymonitoringhost" yaml:"SummaryMonitoringHost"`
		SummaryMonitoringPort int `mapstructure:"summarymonitoringport" yaml:"SummaryMonitoringPort"`
	} `mapstructure:"xrootd" yaml:"Xrootd"`
}


type configWithType struct {
	Cache struct {
		BlocksToPrefetch struct { Type string; Value int }
		Concurrency struct { Type string; Value int }
		DataLocation struct { Type string; Value string }
		DataLocations struct { Type string; Value []string }
		DefaultCacheTimeout struct { Type string; Value time.Duration }
		EnableLotman struct { Type string; Value bool }
		EnableOIDC struct { Type string; Value bool }
		EnableVoms struct { Type string; Value bool }
		ExportLocation struct { Type string; Value string }
		HighWaterMark struct { Type string; Value string }
		LocalRoot struct { Type string; Value string }
		LowWatermark struct { Type string; Value string }
		MetaLocations struct { Type string; Value []string }
		NamespaceLocation struct { Type string; Value string }
		PermittedNamespaces struct { Type string; Value []string }
		Port struct { Type string; Value int }
		RunLocation struct { Type string; Value string }
		SelfTest struct { Type string; Value bool }
		SelfTestInterval struct { Type string; Value time.Duration }
		SentinelLocation struct { Type string; Value string }
		StorageLocation struct { Type string; Value string }
		Url struct { Type string; Value string }
		XRootDPrefix struct { Type string; Value string }
	}
	Client struct {
		DisableHttpProxy struct { Type string; Value bool }
		DisableProxyFallback struct { Type string; Value bool }
		MaximumDownloadSpeed struct { Type string; Value int }
		MinimumDownloadSpeed struct { Type string; Value int }
		SlowTransferRampupTime struct { Type string; Value time.Duration }
		SlowTransferWindow struct { Type string; Value time.Duration }
		StoppedTransferTimeout struct { Type string; Value time.Duration }
		WorkerCount struct { Type string; Value int }
	}
	ConfigDir struct { Type string; Value string }
	ConfigLocations struct { Type string; Value []string }
	Debug struct { Type string; Value bool }
	Director struct {
		AdvertisementTTL struct { Type string; Value time.Duration }
		AssumePresenceAtSingleOrigin struct { Type string; Value bool }
		CachePresenceCapacity struct { Type string; Value int }
		CachePresenceTTL struct { Type string; Value time.Duration }
		CacheResponseHostnames struct { Type string; Value []string }
		CacheSortMethod struct { Type string; Value string }
		CachesPullFromCaches struct { Type string; Value bool }
		CheckCachePresence struct { Type string; Value bool }
		CheckOriginPresence struct { Type string; Value bool }
		DbLocation struct { Type string; Value string }
		DefaultResponse struct { Type string; Value string }
		EnableBroker struct { Type string; Value bool }
		EnableOIDC struct { Type string; Value bool }
		EnableStat struct { Type string; Value bool }
		FilteredServers struct { Type string; Value []string }
		GeoIPLocation struct { Type string; Value string }
		MaxMindKeyFile struct { Type string; Value string }
		MaxStatResponse struct { Type string; Value int }
		MinStatResponse struct { Type string; Value int }
		OriginCacheHealthTestInterval struct { Type string; Value time.Duration }
		OriginResponseHostnames struct { Type string; Value []string }
		StatConcurrencyLimit struct { Type string; Value int }
		StatTimeout struct { Type string; Value time.Duration }
		SupportContactEmail struct { Type string; Value string }
		SupportContactUrl struct { Type string; Value string }
		X509ClientAuthenticationPrefixes struct { Type string; Value []string }
	}
	DisableHttpProxy struct { Type string; Value bool }
	DisableProxyFallback struct { Type string; Value bool }
	Federation struct {
		BrokerUrl struct { Type string; Value string }
		DirectorUrl struct { Type string; Value string }
		DiscoveryUrl struct { Type string; Value string }
		JwkUrl struct { Type string; Value string }
		RegistryUrl struct { Type string; Value string }
		TopologyDowntimeUrl struct { Type string; Value string }
		TopologyNamespaceUrl struct { Type string; Value string }
		TopologyReloadInterval struct { Type string; Value time.Duration }
		TopologyUrl struct { Type string; Value string }
	}
	GeoIPOverrides struct { Type string; Value interface{} }
	Issuer struct {
		AuthenticationSource struct { Type string; Value string }
		AuthorizationTemplates struct { Type string; Value interface{} }
		GroupFile struct { Type string; Value string }
		GroupRequirements struct { Type string; Value []string }
		GroupSource struct { Type string; Value string }
		IssuerClaimValue struct { Type string; Value string }
		OIDCAuthenticationRequirements struct { Type string; Value interface{} }
		OIDCAuthenticationUserClaim struct { Type string; Value string }
		OIDCGroupClaim struct { Type string; Value string }
		QDLLocation struct { Type string; Value string }
		ScitokensServerLocation struct { Type string; Value string }
		TomcatLocation struct { Type string; Value string }
		UserStripDomain struct { Type string; Value bool }
	}
	IssuerKey struct { Type string; Value string }
	LocalCache struct {
		DataLocation struct { Type string; Value string }
		HighWaterMarkPercentage struct { Type string; Value int }
		LowWaterMarkPercentage struct { Type string; Value int }
		RunLocation struct { Type string; Value string }
		Size struct { Type string; Value string }
		Socket struct { Type string; Value string }
	}
	Logging struct {
		Cache struct {
			Http struct { Type string; Value string }
			Ofs struct { Type string; Value string }
			Pfc struct { Type string; Value string }
			Pss struct { Type string; Value string }
			Scitokens struct { Type string; Value string }
			Xrd struct { Type string; Value string }
			Xrootd struct { Type string; Value string }
		}
		DisableProgressBars struct { Type string; Value bool }
		Level struct { Type string; Value string }
		LogLocation struct { Type string; Value string }
		Origin struct {
			Cms struct { Type string; Value string }
			Http struct { Type string; Value string }
			Ofs struct { Type string; Value string }
			Oss struct { Type string; Value string }
			Scitokens struct { Type string; Value string }
			Xrd struct { Type string; Value string }
			Xrootd struct { Type string; Value string }
		}
	}
	Lotman struct {
		DbLocation struct { Type string; Value string }
		EnableAPI struct { Type string; Value bool }
		LibLocation struct { Type string; Value string }
		Lots struct { Type string; Value interface{} }
	}
	MinimumDownloadSpeed struct { Type string; Value int }
	Monitoring struct {
		AggregatePrefixes struct { Type string; Value []string }
		DataLocation struct { Type string; Value string }
		DataRetention struct { Type string; Value time.Duration }
		MetricAuthorization struct { Type string; Value bool }
		PortHigher struct { Type string; Value int }
		PortLower struct { Type string; Value int }
		PromQLAuthorization struct { Type string; Value bool }
		TokenExpiresIn struct { Type string; Value time.Duration }
		TokenRefreshInterval struct { Type string; Value time.Duration }
	}
	OIDC struct {
		AuthorizationEndpoint struct { Type string; Value string }
		ClientID struct { Type string; Value string }
		ClientIDFile struct { Type string; Value string }
		ClientRedirectHostname struct { Type string; Value string }
		ClientSecretFile struct { Type string; Value string }
		DeviceAuthEndpoint struct { Type string; Value string }
		Issuer struct { Type string; Value string }
		TokenEndpoint struct { Type string; Value string }
		UserInfoEndpoint struct { Type string; Value string }
	}
	Origin struct {
		DbLocation struct { Type string; Value string }
		DirectorTest struct { Type string; Value bool }
		EnableBroker struct { Type string; Value bool }
		EnableCmsd struct { Type string; Value bool }
		EnableDirListing struct { Type string; Value bool }
		EnableDirectReads struct { Type string; Value bool }
		EnableFallbackRead struct { Type string; Value bool }
		EnableIssuer struct { Type string; Value bool }
		EnableListings struct { Type string; Value bool }
		EnableMacaroons struct { Type string; Value bool }
		EnableOIDC struct { Type string; Value bool }
		EnablePublicReads struct { Type string; Value bool }
		EnableReads struct { Type string; Value bool }
		EnableUI struct { Type string; Value bool }
		EnableVoms struct { Type string; Value bool }
		EnableWrite struct { Type string; Value bool }
		EnableWrites struct { Type string; Value bool }
		ExportVolume struct { Type string; Value string }
		ExportVolumes struct { Type string; Value []string }
		Exports struct { Type string; Value interface{} }
		FederationPrefix struct { Type string; Value string }
		GlobusClientIDFile struct { Type string; Value string }
		GlobusClientSecretFile struct { Type string; Value string }
		GlobusCollectionID struct { Type string; Value string }
		GlobusCollectionName struct { Type string; Value string }
		GlobusConfigLocation struct { Type string; Value string }
		HttpAuthTokenFile struct { Type string; Value string }
		HttpServiceUrl struct { Type string; Value string }
		Mode struct { Type string; Value string }
		Multiuser struct { Type string; Value bool }
		NamespacePrefix struct { Type string; Value string }
		Port struct { Type string; Value int }
		RunLocation struct { Type string; Value string }
		S3AccessKeyfile struct { Type string; Value string }
		S3Bucket struct { Type string; Value string }
		S3Region struct { Type string; Value string }
		S3SecretKeyfile struct { Type string; Value string }
		S3ServiceName struct { Type string; Value string }
		S3ServiceUrl struct { Type string; Value string }
		S3UrlStyle struct { Type string; Value string }
		ScitokensDefaultUser struct { Type string; Value string }
		ScitokensMapSubject struct { Type string; Value bool }
		ScitokensNameMapFile struct { Type string; Value string }
		ScitokensRestrictedPaths struct { Type string; Value []string }
		ScitokensUsernameClaim struct { Type string; Value string }
		SelfTest struct { Type string; Value bool }
		SelfTestInterval struct { Type string; Value time.Duration }
		StoragePrefix struct { Type string; Value string }
		StorageType struct { Type string; Value string }
		Url struct { Type string; Value string }
		XRootDPrefix struct { Type string; Value string }
		XRootServiceUrl struct { Type string; Value string }
	}
	Plugin struct {
		Token struct { Type string; Value string }
	}
	Registry struct {
		AdminUsers struct { Type string; Value []string }
		CustomRegistrationFields struct { Type string; Value interface{} }
		DbLocation struct { Type string; Value string }
		Institutions struct { Type string; Value interface{} }
		InstitutionsUrl struct { Type string; Value string }
		InstitutionsUrlReloadMinutes struct { Type string; Value time.Duration }
		RequireCacheApproval struct { Type string; Value bool }
		RequireKeyChaining struct { Type string; Value bool }
		RequireOriginApproval struct { Type string; Value bool }
	}
	Server struct {
		EnablePprof struct { Type string; Value bool }
		EnableUI struct { Type string; Value bool }
		ExternalWebUrl struct { Type string; Value string }
		Hostname struct { Type string; Value string }
		IssuerHostname struct { Type string; Value string }
		IssuerJwks struct { Type string; Value string }
		IssuerPort struct { Type string; Value int }
		IssuerUrl struct { Type string; Value string }
		Modules struct { Type string; Value []string }
		RegistrationRetryInterval struct { Type string; Value time.Duration }
		SessionSecretFile struct { Type string; Value string }
		StartupTimeout struct { Type string; Value time.Duration }
		TLSCACertificateDirectory struct { Type string; Value string }
		TLSCACertificateFile struct { Type string; Value string }
		TLSCAKey struct { Type string; Value string }
		TLSCertificate struct { Type string; Value string }
		TLSKey struct { Type string; Value string }
		UIActivationCodeFile struct { Type string; Value string }
		UIAdminUsers struct { Type string; Value []string }
		UILoginRateLimit struct { Type string; Value int }
		UIPasswordFile struct { Type string; Value string }
		WebConfigFile struct { Type string; Value string }
		WebHost struct { Type string; Value string }
		WebPort struct { Type string; Value int }
	}
	Shoveler struct {
		AMQPExchange struct { Type string; Value string }
		AMQPTokenLocation struct { Type string; Value string }
		Enable struct { Type string; Value bool }
		IPMapping struct { Type string; Value interface{} }
		MessageQueueProtocol struct { Type string; Value string }
		OutputDestinations struct { Type string; Value []string }
		PortHigher struct { Type string; Value int }
		PortLower struct { Type string; Value int }
		QueueDirectory struct { Type string; Value string }
		StompCert struct { Type string; Value string }
		StompCertKey struct { Type string; Value string }
		StompPassword struct { Type string; Value string }
		StompUsername struct { Type string; Value string }
		Topic struct { Type string; Value string }
		URL struct { Type string; Value string }
		VerifyHeader struct { Type string; Value bool }
	}
	StagePlugin struct {
		Hook struct { Type string; Value bool }
		MountPrefix struct { Type string; Value string }
		OriginPrefix struct { Type string; Value string }
		ShadowOriginPrefix struct { Type string; Value string }
	}
	TLSSkipVerify struct { Type string; Value bool }
	Transport struct {
		DialerKeepAlive struct { Type string; Value time.Duration }
		DialerTimeout struct { Type string; Value time.Duration }
		ExpectContinueTimeout struct { Type string; Value time.Duration }
		IdleConnTimeout struct { Type string; Value time.Duration }
		MaxIdleConns struct { Type string; Value int }
		ResponseHeaderTimeout struct { Type string; Value time.Duration }
		TLSHandshakeTimeout struct { Type string; Value time.Duration }
	}
	Xrootd struct {
		AuthRefreshInterval struct { Type string; Value time.Duration }
		Authfile struct { Type string; Value string }
		ConfigFile struct { Type string; Value string }
		DetailedMonitoringHost struct { Type string; Value string }
		DetailedMonitoringPort struct { Type string; Value int }
		LocalMonitoringHost struct { Type string; Value string }
		MacaroonsKeyFile struct { Type string; Value string }
		ManagerHost struct { Type string; Value string }
		ManagerPort struct { Type string; Value int }
		MaxStartupWait struct { Type string; Value time.Duration }
		Mount struct { Type string; Value string }
		Port struct { Type string; Value int }
		RobotsTxtFile struct { Type string; Value string }
		RunLocation struct { Type string; Value string }
		ScitokensConfig struct { Type string; Value string }
		Sitename struct { Type string; Value string }
		SummaryMonitoringHost struct { Type string; Value string }
		SummaryMonitoringPort struct { Type string; Value int }
	}
}
