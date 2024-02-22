import {Namespace} from "@/components/Main";
import Card from "./Card";
import CacheCard from "./CacheCard";
import OriginCard from "./OriginCard";
import CreateNamespaceCard from "./CreateNamespaceCard";
import CardSkeleton from "./CardSkeleton";
import PendingCard from "./PendingCard";
import CardList from "./CardList";

export {
    Card, CacheCard, CardList, CreateNamespaceCard, CardSkeleton, PendingCard, OriginCard
}


export const getServerType = (namespace: Namespace) => {

    // If the namespace is empty the value is undefined
    if (namespace?.prefix == null || namespace.prefix == ""){
        return ""
    }

    // If the namespace prefix starts with /cache, it is a cache server
    if (namespace.prefix.startsWith("/cache")) {
        return "cache"
    }

    // Otherwise it is an origin server
    return "origin"

}
