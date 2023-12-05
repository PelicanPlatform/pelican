import React from "react";

import fs from "fs"
import path from "path"
import SwaggerUI from "./SwaggerUI";
import "swagger-ui-react/swagger-ui.css"

const pelicanSwaggerPath = "../../../../../../../swagger/pelican-swagger.yaml"

function Page() {

    const pelicanSwagger = fs.readFileSync(path.resolve(__dirname, pelicanSwaggerPath), "utf-8")

    return <SwaggerUI spec={pelicanSwagger} />
}

export default Page