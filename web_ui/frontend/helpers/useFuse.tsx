import {useMemo} from 'react'
import Fuse, {IFuseOptions} from 'fuse.js'

/**
 * A utility function to get all keys of an object recursively returning a array of keys with . notation
 */
function getKeys(obj: any, parentKey: string = ''): string[] {
    let keys: string[] = []
    for (const key in obj) {
        if (typeof obj[key] === 'object') {
            keys = keys.concat(getKeys(obj[key], parentKey + key + '.'))
        } else {
            keys.push(parentKey + key)
        }
    }
    return keys
}

/**
 * A React Hook that filters an array using the Fuse.js fuzzy-search library.
 *
 * @param list The array to filter.
 * @param searchTerm The search term to filter by.
 * @param fuseOptions Options for Fuse.js.
 *
 * @returns The filtered array.
 *
 * @see https://fusejs.io/
 */
function useFuse<T>(
    list: T[],
    searchTerm: string,
    fuseOptions: IFuseOptions<T> = {}
) {

    const keys = useMemo(() : string[] => {
        if (list.length > 0) {
            return getKeys(list[0])
        }
        return []
    }, [list])

    const options = useMemo(() => {
        return {
            ...fuseOptions,
            keys: keys
        }
    }, [fuseOptions, keys])

    const fuse = useMemo(() => {
        return new Fuse(list, options)
    }, [list, options])

    const results = useMemo(() => {
        if(searchTerm === '') {
            return list
        }
        return fuse.search(searchTerm).map(result => result.item)
    }, [fuse, searchTerm])

    return results
}

export default useFuse
