
if(!process.env.VERSIONS && process.env.NODE_ENV !== 'development') {
	throw new Exception("Missing required env variable VERSIONS");
} else {
	process.env.VERSIONS = process.env.VERSIONS || "['latest']"
}

const versions = eval(process.env.VERSIONS);

export default {
	"about-pelican": "About Pelican",
	"install": "Installing Pelican",
	"parameters": "Configuration",
	"getting-started": "Getting Started",
	"getting-data-with-pelican": "Getting Data with Pelican",
	"federating-your-data": "Federating Your Data",
	"operating-a-federation": "Operating a Federation",
	"monitoring-pelican-services": "Monitoring Pelican Services",
	"advanced-usage": "Advanced Usage",
	"faq": "FAQs and Troubleshooting",
	"api-docs": "API Documentation",
	"versions": {
		"title": "Versions",
		"type": "menu",
		"items": versions.reverse().reduce((acc, v) => {
			acc[`${v}`] = {
				title: v === 'latest' ? 'Latest' : v,
				href: v === 'latest' ? '/' : `/${v}/`
			}
			return acc
		}, {})
	}
}
