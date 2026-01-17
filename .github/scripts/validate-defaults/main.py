from typing import Any

import yaml

DEFAULTS_FILE = "./config/resources/defaults.yaml"
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


def main():
    with open(DEFAULTS_FILE, mode="r", encoding="utf-8") as fp:
        defaults = flatten_dict(yaml.safe_load(fp.read()))

    with open(PARAMETERS_FILE, mode="r", encoding="utf-8") as fp:
        parameters = yaml.safe_load_all(fp.read())
        parameters = {p["name"]: p for p in parameters}

    errors = []
    for key, default in defaults.items():
        if key not in parameters:
            errors.append(f"Key for default value is not in the parameters file: {key}")
            continue

        # If the defaults file has a value, it must match the parameters
        # file. The reverse need not be true (the default value may be set
        # via other means, i.e., code).
        if default != parameters[key]["default"]:
            errors.append(f"Default value does not match the parameters file: {key}")

    if errors:
        raise RuntimeError("\n" + "\n".join(errors))


if __name__ == "__main__":
    main()
