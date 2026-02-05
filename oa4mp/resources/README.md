# Configuration for OA4MP and its Dependencies

The configuration is a mix of static files that are copied into container images as they are being built, and templates that are compiled into Pelican's binaries and rendered at run time.

## OA4MP

The `oa4mp-config` subdirectory contains the following:

- `web.xml`: The template for the configuration file that [Apache Tomcat](https://tomcat.apache.org/) uses to deploy [OA4MP](https://oa4mp.org/). The version that OA4MP shipped with when this template was created should be recorded in `web.xml.upstream`.

- `cfg.xml`: The template for OA4MP's main configuration file. The version that OA4MP shipped with when this template was created should be recorded in `cfg.xml.upstream`.

Notable changes that Pelican makes to the upstream versions:

- `web.xml`:

  - Remove security constraints on endpoints. Assume that Pelican, as the proxy for all traffic, will enforce constraints as needed.

  - Add directives for indicating the location of OA4MP's main configuration file.

- `cfg.xml`:

  - Replace hard-coded URLs and paths with variables.

  - Enable the HTTP-header based authorization servlet. Set the header's name.

  - Configure client management to auto-approve registrations. Set the template's name.

  - Configure unused client cleanup.

  - Configure logging to go to `/dev/stdout`. Pelican should consume the output and log it as needed.

  - Assorted tweaks to default values.

### Web pages

The `jsp-overrides` subdirectory contains the following:

- Assorted [JSPs](https://projects.eclipse.org/projects/ee4j.jsp) that replace some of OA4MP's pages with versions that match Pelican's look and feel.

### OAuth2 clients

The `oa4mp-config` subdirectory contains the following:

- `client-template.xml`: The template/prototype used by OA4MP when setting up a dynamically registered OAuth2 client.

The `qdl-scripts` subdirectory contains the following:

- `boot.qdl`: The [QDL](https://qdl-lang.org/) script that imports the above template into OA4MP's client store.

- `id_token_policies.qdl` and `policies.qdl`: The QDL scripts that set various claims in tokens returned to clients based on the above template.

## Apache Tomcat

The `tomcat-config` subdirectory contains the following:

- `server.xml`: The template for the server's main configuration file. The version that Tomcat shipped with when this template was created should be recorded in `server.xml.upstream`.

Notable changes that Pelican makes to the upstream versions:

- Listen on a UNIX domain socket. Pelican proxies all traffic through this socket.

- Disable the shutdown port. (Why?)

- Disable the APR connector. (It doesn't work out of the box?)

- Disable logging. Pelican takes care of access logging.

## Upgrading OA4MP and its Dependencies

From a development standpoint, the main difficulty here is identifying and tracking the changes that need to be made to the default configuration files that these applications ship with.

Relative to the root directory of this repository:

1. Update the versions in `images/Dockerfile`.

1. Build the `origin` image:

   ```
   docker build --target origin -t pelican-origin:local -f images/Dockerfile .
   ```

1. Exec into the image that was just built:

   ```
   docker run -it --rm -v ${PWD}:/app --entrypoint /bin/bash pelican-origin:local
   ```

1. Copy the following configuration files to their corresponding `*.upstream` files in `/app/oa4mp/resources`:

   - `/opt/scitokens-server/etc/cfg.xml`
   - `/opt/tomcat/conf/server.xml`
   - `/opt/tomcat/webapps/scitokens-server/WEB-INF/web.xml`

1. Use the output from `git diff` on each `*.upstream` file to determine how to update the corresponding template.

1. Commit any changes.
