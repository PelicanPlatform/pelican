import yaml

PARAMETER_PATH = './docs/parameters.yaml'

KEYS = ["name", "description", "type", "default", "components"]

ENUMERATIONS = {
    "type": ('url', 'object', 'filename', 'int', 'stringSlice', 'duration', 'string', 'bool')
}

VERIFIED_OBJECT_STRUCTURES = [
    "GeoIPOverrides",
    "Institutions",
    "CustomRegistrationFields",
    "OIDCAuthenticationRequirements",
    "AuthorizationTemplates",
    "IPMapping",
    "Exports",
    "PolicyDefinitions",
]


def main():

    errors = []

    with open(PARAMETER_PATH, 'r') as file:
        for parameter in yaml.load_all(file, Loader=yaml.FullLoader):

            if not all(key in parameter for key in KEYS):
                errors.append(f"Parameter is missing a required key: {parameter['name']}")
                continue

            if type(parameter['name']) != str:
                errors.append(f"Parameter name is not a string: {parameter['name']}")
                continue

            if type(parameter['description']) != str:
                errors.append(f"Parameter description is not a string: {parameter['name']}")
                continue

            if type(parameter['components']) != list:
                errors.append(f"Parameter component is not a list: {parameter['name']}")
                continue

            if parameter['type'] not in ENUMERATIONS['type']:
                errors.append(f"Parameter type is not a recorded type. Please add web dev as a reviewer: {parameter['name']}")
                continue

            if parameter['type'] == 'object':

                object_structure = parameter['name'].split(".")[-1]

                if object_structure not in VERIFIED_OBJECT_STRUCTURES:
                    errors.append(f"Parameter objectStructure is not verified. Web Dev must create new config ui for: {object_structure}")
                    continue

        if len(errors) != 0:
            raise Exception("\n" + "\n".join(errors))


if __name__ == '__main__':
    main()
