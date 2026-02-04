import yaml

PARAMETERS_FILE = "./docs/parameters.yaml"

# These fields are required in every parameter's definition.
KEYS = ["name", "description", "type", "default", "components"]

# Some of the above fields have a restricted range of values.
ENUMERATIONS = {
    "components": [
        "*",
        "broker",
        "cache",
        "client",
        "director",
        "localcache",
        "origin",
        "plugin",
        "registry",
    ],
    "type": [
        "bool",
        "duration",
        "filename",
        "int",
        "object",
        "string",
        "stringSlice",
        "url",
    ],
}

# Parameters whose type is "object" require special handling in order to be
# configurable via Pelican's web UI. The ones in this list are known to have
# beeh handled appropriately.
VERIFIED_OBJECT_STRUCTURES = [
    "GeoIPOverrides",
    "Issuer.AuthorizationTemplates",
    "Issuer.OIDCAuthenticationRequirements",
    "Lotman.PolicyDefinitions",
    "Origin.Exports",
    "Registry.CustomRegistrationFields",
    "Registry.Institutions",
    "Shoveler.IPMapping",
]


def main():
    with open(PARAMETERS_FILE, mode="r", encoding="utf-8") as fp:
        parameters = yaml.safe_load_all(fp.read())

    errors = []
    for parameter in parameters:
        if missing := set(KEYS) - set(parameter):
            errors.append(f"{PARAMETERS_FILE}: {parameter}: Missing required keys: {missing}")
            continue
        name = parameter["name"]

        if not isinstance(parameter["name"], str):
            errors.append(f"{PARAMETERS_FILE}: {name}: Name is not a string")

        if not isinstance(parameter["description"], str):
            errors.append(f"{PARAMETERS_FILE}: {name}: Description is not a string")

        if parameter["type"] not in ENUMERATIONS["type"]:
            errors.append(f"{PARAMETERS_FILE}: {name}: Type is not one of {ENUMERATIONS['type']}")

        if not isinstance(parameter["components"], list):
            errors.append(f"{PARAMETERS_FILE}: {name}: Components is not a list")
        elif unknown := set(parameter["components"]) - set(ENUMERATIONS["components"]):
            errors.append(f"{PARAMETERS_FILE}: {name}: Some components are not recognized: {unknown}")

        if parameter["type"] == "object" and parameter["name"] not in VERIFIED_OBJECT_STRUCTURES:
            errors.append(f"Parameter's object structure not verified for configuration via the web UI; please contact a web developer: {parameter['name']}")

    if errors:
        raise RuntimeError("\n" + "\n".join(errors))


if __name__ == "__main__":
    main()
