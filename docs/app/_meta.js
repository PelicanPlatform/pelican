if(!process.env.VERSIONS && process.env.NODE_ENV !== 'development') {
	throw new Exception("Missing required env variable VERSIONS");
} else {
	process.env.VERSIONS = process.env.VERSIONS || "['latest']"
}

const versions = eval(process.env.VERSIONS);

export default {
	// Canonical sources for pages that more than one section carries. Next.js does
	// not route "_"-prefixed folders, and "display: hidden" keeps them out of the
	// page map, so these files are reachable only through the section stubs that
	// re-export them.
	"_shared": { "display": "hidden" },

	// app/page.tsx is a redirect, not a doc page
	"index": { "display": "hidden" },

	"accessing-your-data": { "type": "page", "title": "Accessing Your Data" },
	"sharing-your-data": { "type": "page", "title": "Sharing Your Data" },
	"federation-services": { "type": "page", "title": "Running Federation Services" },

	"versions": {
		"title": "Versions",
		"type": "menu",
		"items": versions.reverse().reduce((acc, v) => {
			acc[`${v}`] = {
				title: v === 'latest' ? 'Latest' : v,
				href: v === 'latest' ? '/' : `https://docs.pelicanplatform.org/${v}/`
			}
			return acc
		}, {})
	}
}
