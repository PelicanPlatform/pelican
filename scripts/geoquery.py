#!/usr/bin/env python3

import argparse

import geoip2.database
import geoip2.errors


def resolve_ip(database_path, ip_address):
    try:
        with geoip2.database.Reader(database_path) as reader:
            response = reader.city(ip_address)
            print(f"IP address {ip_address} is resolvable.")
            print(f"City: {response.city.name}")
            print(f"Country: {response.country.name}")
            print(f"Latitude: {response.location.latitude}")
            print(f"Longitude: {response.location.longitude}")
            print(f"Accuracy Radius: {response.location.accuracy_radius}")
    except geoip2.errors.AddressNotFoundError:
        print(f"IP address {ip_address} is not resolvable.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Resolve IP address using GeoIP2 database.")
    parser.add_argument(
        "-d",
        "--db-path",
        help="Path to the GeoIP2 database file",
        default="/var/cache/pelican/maxmind/GeoLite2-City.mmdb",
    )
    parser.add_argument(
        "-i",
        "--ip",
        help="IP address to resolve",
        required=True,
    )

    args = parser.parse_args()

    resolve_ip(args.db_path, args.ip)
