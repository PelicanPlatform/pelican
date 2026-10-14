/**
 * Rail widths, in pixels.
 *
 * The rail follows the window-size guidance for navigation rails: at medium
 * widths it stays collapsed to icons, and once there is room it expands so
 * every destination carries its label. Both breakpoints live here because
 * `Main` has to reserve exactly the space the rail occupies -- when these two
 * drift apart the content either hides behind the rail or floats away from it.
 */
export const RAIL_WIDTH_COLLAPSED = 72;
// Wide enough for the longest label in the config ("Denied Namespaces") to sit
// beside its icon without truncating.
export const RAIL_WIDTH_EXPANDED = 248;

/**
 * Breakpoint-keyed width, shared verbatim by the rail and by the margin `Main`
 * uses to clear it.
 */
export const RAIL_WIDTH = {
  md: `${RAIL_WIDTH_COLLAPSED}px`,
  lg: `${RAIL_WIDTH_EXPANDED}px`,
};

/**
 * Labels are hidden while the rail is collapsed and shown once it expands.
 * Icon-only items keep their tooltip, but a tooltip is not reachable by touch
 * and cannot be scanned, so it is a fallback for the collapsed state rather
 * than the primary way a destination is named.
 */
export const RAIL_LABEL_DISPLAY = { md: 'none', lg: 'block' };
