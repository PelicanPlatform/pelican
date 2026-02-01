from typing import Any

import yaml

DEFAULTS_FILE = "./config/resources/defaults.yaml"
OSDF_DEFAULTS_FILE = "./config/resources/osdf.yaml"
PARAMETERS_FILE = "./docs/parameters.yaml"


def flatten_dict(x: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key, value in x.items():
        if isinstance(value, dict):
            for key2, value2 in flatten_dict(value).items():
                result[f"{key}.{key2}"] = value2
        else:
            result[key] = value
    return result


def check_one_file(defaults_file: str, parameters_key: str) -> list[str]:
    with open(defaults_file, mode="r", encoding="utf-8") as fp:
        defaults = flatten_dict(yaml.safe_load(fp.read()))

    with open(PARAMETERS_FILE, mode="r", encoding="utf-8") as fp:
        parameters = yaml.safe_load_all(fp.read())
        parameters = {p["name"]: p for p in parameters}

    errors = []
    for key, default in defaults.items():
        if key not in parameters:
            errors.append(f"{defaults_file}: {key}: Not a parameter in '{PARAMETERS_FILE}'")
            continue

        if parameters_key not in parameters[key]:
            errors.append(f"{defaults_file}: {key}: The '{parameters_key}' key is not in '{PARAMETERS_FILE}'")
            continue

        # If the defaults file has a value, it must match the parameters
        # file. The reverse need not be true (the default value may be set
        # via other means, i.e., code).
        if default != (val := parameters[key][parameters_key]):
            errors.append(f"{defaults_file}: {key}: Expected '{default}', but found '{val}' for '{parameters_key}' in '{PARAMETERS_FILE}'")

    return errors


def main():
    errors = []
    errors.extend(check_one_file(DEFAULTS_FILE, "default"))
    errors.extend(check_one_file(OSDF_DEFAULTS_FILE, "osdf_default"))

    if errors:
        raise RuntimeError("\n" + "\n".join(errors))


if __name__ == "__main__":
    main()
