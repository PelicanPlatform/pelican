import {
  Config,
  ParameterMetadata,
  ParameterInputProps,
  ParameterMetadataList,
  ParameterMetadataRecord,
  Export,
} from '@/components/configuration';

/**
 * The parameters are stored as a list keyed by the parameter name. This function
 * converts the list into a record that is keyed by the parameter name. This
 * parameter name can be resolved to multiple keys.
 * @param metadata
 */
export const convertFlatConfigToRecord = (metadata: ParameterMetadataList) => {
  let metadataRecord: ParameterMetadataRecord = {};

  metadata.forEach((record) => {
    const [key, value] = Object.entries(record)[0];
    const keys = key.split('.');
    const lastKey = keys.pop() as string;
    let current: Record<string, any> = metadataRecord;
    keys.forEach((k) => {
      if (!current[k]) {
        current[k] = {};
      }
      current = current[k];
    });
    current[lastKey] = value;
  });

  return metadataRecord;
};

/**
 * Recursively replace all objects of type { Type: any, Value: any } with the value of Value
 * @param config
 */
export const stripTypes = (config: any) => {
  if (config?.Value !== undefined && config?.Type !== undefined) {
    return config.Value;
  }

  Object.keys(config).forEach((key) => {
    config[key] = stripTypes(config[key]);
  });

  return config;
};

/** Recursively delete the keys that have null values in an object */
export const stripNulls = (config: any) => {
  // If the config is an object then iterate keys otherwise skip
  if (typeof config !== 'object') {
    return config;
  }

  Object.keys(config).forEach((key) => {
    if (config[key] === null) {
      delete config[key];
    } else {
      config[key] = stripNulls(config[key]);
    }
  });

  return config;
};

/**
 * Check if a value is a Config value or a ParameterInputProps value
 * @param value
 */
export const isParameterMetadata = (
  value: ExpandedObject<ParameterMetadata> | ParameterMetadata
): boolean => {
  return (value as Config)?.type !== undefined;
};

/**
 * Sort the config values so that Config values are at the end and in alphabetical order
 * @param a
 * @param b
 */
export function sortMetadata(
  a: [string, ExpandedObject<ParameterMetadata> | ParameterMetadata],
  b: [string, ExpandedObject<ParameterMetadata> | ParameterMetadata]
) {
  if (!isParameterMetadata(a[1]) && isParameterMetadata(b[1])) {
    return 1;
  }
  if (isParameterMetadata(a[1]) && !isParameterMetadata(b[1])) {
    return -1;
  }
  return a[0].localeCompare(b[0]);
}

/**
 * Delete a key from an object recursively
 * @param obj
 * @param key
 */
export function deleteKey(
  obj: Record<string, any | Record<string, any>>,
  key: string[]
) {
  if (key.length === 1) {
    delete obj[key[0]];
    return;
  } else {
    deleteKey(obj[key[0]], key.slice(1));
    if (Object.keys(obj[key[0]]).length === 0) {
      delete obj[key[0]];
    }
  }
}

type NestedRecord = { [k: string]: any | undefined | NestedRecord };

/**
 * Update a value in an object recursively
 * @param obj
 * @param key
 * @param value
 */
export function updateValue(obj: NestedRecord, key: string[], value: any) {
  if (key.length === 1) {
    obj[key[0]] = { ...value, ...obj[key[0]] };
    return;
  } else {
    updateValue(obj[key[0]], key.slice(1), value);
  }
}

type GeneralNestedRecord<T> = { [k: string]: T | GeneralNestedRecord<T> };

/**
 * Drill down into an object and return a list of keys that point to objects
 * that pass a function check
 */
export function objectDrill<T>(
  obj: GeneralNestedRecord<T>,
  check: (value: T | any) => boolean
): string[][] {
  let keys: string[][] = [];
  Object.entries(obj).forEach(([key, value]) => {
    if (check(value)) {
      keys.push([key]);
    } else {
      keys = keys.concat(
        objectDrill(value as GeneralNestedRecord<T>, check).map((k) => [
          key,
          ...k,
        ])
      );
    }
  });

  return keys;
}

/*
 * Flatten object so that all nested objects have keys in the first level
 *
 * For example:
 *
 * {
 *  a: {
 *   b: 1
 *  }
 * }
 *
 * becomes
 *
 * {
 *  a.b: 1
 * }
 */
export const flattenObject = (object: any): Record<string, any> => {
  let flatObject: Record<string, any> = {};
  for (const [key, value] of Object.entries(object)) {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const nestedObject = flattenObject(value);
      for (const [nestedKey, nestedValue] of Object.entries(nestedObject)) {
        flatObject[key + '.' + nestedKey] = nestedValue;
      }
    } else {
      flatObject[key] = value;
    }
  }
  return flatObject;
};

export type ExpandedObject<T> = { [k: string]: T | ExpandedObject<T> };

/*
 * Expand object so that all keys with dots are nested objects
 */
export function expandObject<T>(object: Record<string, T>): ExpandedObject<T> {
  let expandedObject: ExpandedObject<T> = {};
  for (const [key, value] of Object.entries(object)) {
    const keys = key.split('.');
    let currentObject = expandedObject;
    keys.forEach((key, index) => {
      if (index === keys.length - 1) {
        currentObject[key] = value;
      } else {
        if (!currentObject[key]) {
          currentObject[key] = {};
        }
        currentObject = currentObject[key] as ExpandedObject<T>;
      }
    });
  }
  return expandedObject;
}
