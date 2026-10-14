/**
 * A link is active when its href is a prefix of the current pathname, or --
 * when the entry sets `exactMatch` -- only when the two are equal.
 *
 * Every navigation surface has to agree on this, otherwise the rail, the
 * burger menu and the Settings sub-navigation each highlight a different
 * item for the same URL.
 *
 * `exactMatch` is a property of the entry rather than of the href because the
 * same href legitimately wants both behaviours: `/settings/` is the whole
 * Administration section in the rail (prefix -- stay lit anywhere beneath it)
 * and the single "General" page in the Settings sub-navigation (exact --
 * otherwise it outshines whichever sub-page you are actually on).
 *
 * @param href the destination's href, already evaluated to a string
 * @param pathname the current pathname, from `usePathname()`
 * @param exactMatch true when only the destination's own page counts
 */
export const isActive = (
  href: string,
  pathname: string,
  exactMatch = false
): boolean => (exactMatch ? pathname === href : pathname.startsWith(href));
