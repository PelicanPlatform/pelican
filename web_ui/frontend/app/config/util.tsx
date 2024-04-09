import {ConfigMetadata} from "@/components/Config/index.d";

export const getConfigMetadata = async () => {
    try {
        const res = await fetch("/view/data/parameters.json")
        const data = await res.json() as ConfigMetadata[]
        const metadata = data.reduce((acc: ConfigMetadata, curr: ConfigMetadata) => {
            const [key, value] = Object.entries(curr)[0]
            acc[key] = value
            return acc
        }, {})

        return metadata
    } catch {
        return undefined
    }
}
