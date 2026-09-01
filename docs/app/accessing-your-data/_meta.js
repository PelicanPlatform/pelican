export default {
    "orientation": { "type": "separator", "title": "Start Here" },
    "overview": "Overview",
    "getting-started": "Getting Started",
    "about-pelican": "About Pelican",
    "install": "Installing Pelican",

    "tasks": { "type": "separator", "title": "Working With Data" },
    "accessing-data": "Accessing Data",
    "command-line": "Command Line Client",
    "fsspec": "Python FSSpec",
    "protected-data": "Working with Protected Data",
    "htcondor-plugin": "HTCondor Plugin",

    "background": { "type": "separator", "title": "How It Works" },
    "authorization": "Pelican's Authorization System",

    "reference": { "type": "separator", "title": "Reference" },
    // The page lives at /client/configuration; the sidebar links to it with the
    // client filter preselected. A meta "href" is ignored on a key backed by a
    // real page, so the page entry is hidden and the link is a separate key.
    "configuration": { "display": "hidden" },
    "configuration-client": { "title": "Configuration", "href": "/accessing-your-data/configuration?component=client" },
    "commands-reference": "Commands Reference",

    "help": { "type": "separator", "title": "Help" },
    "faqs": "FAQs",
    "troubleshooting": "Troubleshooting",
}
