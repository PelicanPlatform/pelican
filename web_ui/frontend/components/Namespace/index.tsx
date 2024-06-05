import {Namespace} from "@/index";
import Card from "./Card";
import CreateNamespaceCard from "./CreateNamespaceCard";
import CardSkeleton from "./CardSkeleton";
import PendingCard from "./PendingCard";
import NamespaceCardList from "./NamespaceCardList";
import NamespaceIcon from "./NamespaceIcon";

export {
    Card, NamespaceCardList, CreateNamespaceCard, CardSkeleton, PendingCard, NamespaceIcon
}


export const getServerType = (namespace: Namespace) => {

    // If the namespace is empty the value is undefined
    if (namespace?.prefix == null || namespace.prefix == ""){
        return ""
    }

    // If the namespace prefix starts with /cache, it is a cache server
    if (namespace.prefix.startsWith("/caches/")) {
        return "cache"
    }

    // Otherwise it is an origin server
    return "origin"

}
