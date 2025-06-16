import {DateTime} from "luxon";

/**
 * Returns a string like `UTC-5` based on the current local time zone offset
 */
const getUtcOffsetString = (): string => {
	return `UTC${DateTime.local().offset >= 0 ? '+' : ''}${DateTime.local().offset / 60}`
}

export default getUtcOffsetString;
