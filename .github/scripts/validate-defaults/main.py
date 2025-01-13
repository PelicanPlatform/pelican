import yaml


def main():
    """Validate the defaults file."""

    defaults = yaml.safe_load(open("./config/resources/defaults.yaml"))
    defaults = flatten_dictionary(defaults)

    parameters = yaml.load_all(open("./docs/parameters.yaml"), Loader=yaml.FullLoader)
    parameters = {parameter["name"]: parameter for parameter in parameters}

    error_list = []
    for d_key, d_value in defaults.items():

        if d_key not in parameters:
            error_list.append(f"Parameter {d_key} is not in the parameters file.")

        # Check if the default value is different from the parameters file
        if (
            (parameters[d_key]['default'] != d_value and parameters[d_key]['default'] != 'none') or
            (parameters[d_key]['default'] == 'none' and d_value != "")
        ):

            error_list.append(f"Parameter[{d_key}]: {parameters[d_key]['default']} != {d_value}")

    if error_list:
        raise Exception("\n" + "\n".join(error_list))


def flatten_dictionary(x: dict):
    """Flatten a dictionary."""
    out = {}
    for key, value in x.items():
        if isinstance(value, dict):
            for key2, value2 in flatten_dictionary(value).items():
                out[f"{key}.{key2}"] = value2
        else:
            out[key] = value
    return out


if __name__ == "__main__":
    main()
