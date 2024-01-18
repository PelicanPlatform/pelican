import React from "react";
import 'server-only'

import fs from "fs"
import path from "path"
import SwaggerUI from "./SwaggerUI";
import "swagger-ui-react/swagger-ui.css"

const pelicanSwaggerPath = "app/api/docs/pelican-swagger.yaml"

function Page() {
    const pelicanSwagger = fs.readFileSync(path.resolve(process.cwd(), pelicanSwaggerPath), "utf-8")
    return <SwaggerUI spec={pelicanSwagger} />
}

export default Page
