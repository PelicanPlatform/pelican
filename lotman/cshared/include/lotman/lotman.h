/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

/**
 * Public header for the LotMan C library.
 *
 * This is the interface libLotMan publishes to external C and C++ consumers --
 * most notably the XRootD pfc purge plugin (xrootd-lotman), which compiles
 * `#include <lotman/lotman.h>`. Pelican's implementation of it lives in
 * lotman/cshared, a cgo c-shared build over the native Go lot engine.
 *
 * The declarations below are those of the original C++ libLotMan at v0.1.0
 * (src/lotman.h in https://github.com/PelicanPlatform/lotman, Apache-2.0), kept
 * verbatim so a consumer compiled against either library gets the same ABI.
 *
 * It is NOT the header cgo generates. cgo emits `_Bool` (not a C++ type), drops
 * every `const`, and writes no `extern "C"` block, so its output does not
 * compile in C++ at all -- and every consumer of this library is C++. The
 * generated header is a build artifact; this file is the published interface,
 * and lotman/cshared/abi_conformance_test.go checks the Go exports against it.
 *
 * Two deliberate differences from the original header, neither of which affects
 * the ABI of any function below:
 *
 *   - It declares `extern std::shared_ptr<int> lotman_db_timeout`, a C++ global
 *     that a C-ABI library cannot export. Set the SQLite busy timeout with
 *     lotman_set_context_int("db_timeout", <ms>, &err) instead.
 *   - It includes <memory> and so cannot be used from C. This one includes
 *     <stdbool.h> and <stdint.h>, which is all the declarations need.
 */

#ifndef LOTMAN_H
#define LOTMAN_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
APIs
*/

const char *lotman_version();
/**
	DESCRIPTION: Returns current version of LotMan
*/

int lotman_lot_exists(const char *lot_name, char **err_msg);
/**
	DESCRIPTION: A function for determining whether a lot exists in the lot database.

	RETURNS: Returns 0 if the lot does not exist, 1 if the lot does exist. Any other
		values indicate an error.

	INPUTS:
	lot_name:
		The name of the lot whose existence is to be determine.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_add_lot(const char *lotman_JSON_str, char **err_msg);
/**
	DESCRIPTION: Function for adding/creating a lot, which gets stored in the lot database.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	lotman_JSON_str:
		A string defining the lot in JSON (see below for lot object specification)

	err_msg:
		A reference to a char array that can store any error messages.

	Lot Object specification:
{   "lot_name":
		REQUIRED: A string indicating the name of the lot.
	"owner":
		REQUIRED: A string indicating the entity that "owns" the contents of the lot. Ownership of a lot
		indicates ownership of the lots contents, but not the lot itself; like renting a garden --
		you own what you grow, but not the dirt you grow it in. A lot owner cannot modify the lot's
		properties unless the lot is a self parent. However, the owner can modify the properties of
		any sub lots.
	"parents":
		REQUIRED: An array of strings indicating any lots that are parent to the lot about to be added.
		Any parents specified must already exist in the lot database, unless the specified parent
		is the lot itself. At least one parent must be specified.
	"children":
		OPTIONAL: An array of strings indicating any lots that are children of the lot about to be added.
		Any children must already exist in the lot database. A lot should not specify itself as
		a child, as this case is already handled by the self parent mechanism.
	"paths":
		OPTIONAL: An array of `path` objects that are used to associate paths/objects to the lot. Each
		path object has the following structure:
		{"path": "/path/to/associate", "recursive": bool, "exclude": bool}
		When "recursive" is true, all subdirectories of the path are also attributed to the lot. When false,
		only non-directory objects below the path should be attributed, but any subdirectories should not be.

		Path-to-lot resolution is dynamic: when several live lots' paths could match a directory, the
		lot whose path is the longest prefix of the query path "wins" (deepest descendant). This means
		a sublot whose path is a strict subpath of an ancestor's recursive path automatically claims its
		subtree without requiring an explicit "exclude" row on the ancestor — and reverts ownership back
		to the ancestor when the sublot is removed or expires.

		Descendancy rule (enforced when adding/updating non-excluded paths): if another live lot's
		recursive path is a strict prefix of the candidate path, the candidate's lot must be a recursive
		descendant of that other lot. Symmetrically, a recursive candidate path that would cover an
		existing lot's path requires that other lot to be a recursive descendant of the candidate.
		Same-path collisions during overlapping time windows are always rejected.

		When "exclude" is true, this path row is an escape hatch: it is ignored by both path resolution
		and the descendancy/temporal-overlap check. Prefer the dynamic-ownership model above over
		explicit exclusions. The "exclude" field is optional and defaults to false if not specified.
	"management_policy_attrs":
		REQUIRED: A JSON object containing the collection of attributes used for creating policies for the
		lot. The object has the following structure:

	{   "dedicated_GB":
			REQUIRED: A double indicating the size in GB of dedicated storage a lot possesses. During a lot's
			lifespan, this is the amount of persistent storage it should be allowed to access.
		"opportunistic_GB":
			REQUIRED: A double indicating the size in GB of opportunistic storage a lot possesses. During a
			lot's lifespan, this is the amount of extra storage it should be able to access after all
			dedicated storage has been exhausted if the system determines there is unused capacity. Opp
			storage should be considered transient, and as such, depending on the management policy, lots
			that are using some amount of opp storage may be subject to purging in the event that the system
			needs to create space.
		"max_num_objects": An int64 indicating the maxiximum number of objects a lot may have attributed to it.

			Sentinel for unbounded MPAs: a value of -1 on a quota MPA marks that resource axis
			as unbounded for this lot. (Note: timestamp MPAs use 0 as a separate sentinel; see
			creation_time below.) MPAs are grouped into independent axes that are validated
			separately:
			  * Storage axis: dedicated_GB and opportunistic_GB are independent storage pools.
				A value of -1 on either axis means "unbounded" on that axis. Because
				opportunistic_GB tracks data ABOVE the dedicated allotment, an unbounded
				dedicated allotment is meaningless without an unbounded opportunistic axis;
				therefore dedicated_GB == -1 requires opportunistic_GB == -1 (any other
				combination with dedicated_GB == -1 is rejected). All other combinations are
				legal:
				  - (dedicated_GB == 0, opportunistic_GB == 0): no storage at all (rare; useful
					mostly as a placeholder).
				  - (dedicated_GB == 0, opportunistic_GB >= 0 or -1): a "purely opportunistic"
					lot with no guaranteed allotment.
				  - (dedicated_GB > 0, opportunistic_GB == 0): finite guaranteed allotment with
					no burst capacity.
				  - (dedicated_GB > 0, opportunistic_GB > 0 or -1): finite guaranteed allotment
					with a finite or unbounded burst.
				  - (dedicated_GB == -1, opportunistic_GB == -1): fully unbounded storage.
			  * Object-count axis (max_num_objects): -1 == unbounded; 0 == no objects allowed.
			Different axes are independent: a lot may be unbounded on one axis and bounded on
			another (e.g. unbounded storage with a finite max_num_objects). Under strict_hierarchy,
			a child that is unbounded on an axis requires every parent to also be unbounded on that
			axis; an unbounded parent absorbs any child allocation on that axis. Lots that are
			unbounded on an axis never appear in past-quota queries for that axis.
		"creation_time":
			REQUIRED: A Unix timestamp in milliseconds indicating when the lot should begin its existence.
			The lot is considered active starting at this time (inclusive). Together with expiration_time,
			this defines a half-open interval [creation_time, expiration_time).
		"expiration_time":
			REQUIRED: A Unix timestamp in milliseconds indicating when the lot "expires". The lot is
			considered active up to, but not including, this time (half-open interval). In a similar vein
			as opp storage, a lot and its storage become transient once expiration time is reached. If
			the system determines there is unused space, the lot may continue to exist, but all storage tied
			to the lot should be considered opportunistic.
		"deletion_time":
			REQUIRED: A Unix timestamp in milliseconds indicating when the lot and its contents should be deleted.

			Sentinel for non-expiring lots: a value of 0 (the Unix epoch) for ANY of creation_time,
			expiration_time, or deletion_time is treated as a sentinel indicating that the lot is
			non-expiring. The sentinel is all-or-nothing: if any of these three timestamps is 0, then
			ALL THREE must be 0. Any mix of 0 and non-zero values is rejected so the database cannot
			be left in an inconsistent state. Non-expiring lots never appear in expired/deletion-time
			queries, are always considered alive, and (under strict_hierarchy) a non-expiring parent
			accepts children with any timestamps (finite or non-expiring). The one directional
			constraint is on non-expiring *children*: a lot with all-zero timestamps may only be
			placed under a parent that is also non-expiring, because an infinite window cannot fit
			inside a finite one.
	}
}
*/

int lotman_remove_lot(const char *lot_name, bool assign_LTBR_parent_as_parent_to_orphans,
					  bool assign_LTBR_parent_as_parent_to_non_orphans, bool assign_policy_to_children,
					  const bool override_policy, char **err_msg);
/**
	DESCRIPTION: Function for deleting a lot, but preserving any children lots. In general, the function to remove
		lots recursively should be favored over this function. When this func is used, LotMan will attempt to handle
		the proper policy/parent reassignments for children lots according to the selection of options. These
		reassignments are necessary to preserve the lot database's structure.
		NOTE: Deleting a lot does not actually affect the objects tied to the lot. It only removes the lot from the
			lot database.
		NOTE: Lotman must be called with the correct context set for a lot to be successfully deleted. When deleting a
			lot, the caller must be set to one of the lot's owners.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	lot_name:
		A string indicating the name of the lot to be removed (LTBR)

	assign_LTBR_parent_as_parent_to_orphans:
		A bool indicating whether LotMan should attempt to assign LTBR's parents as the new parents to any lots
		orphaned by LTBR's removal. If true, any lots whose only parent is currently LTBR will be reassigned to
		have LTBR's parents as explicit parents. If false, any orphans will automatically be reassigned to have
		the default lot as a parent.
		NOTE: If LTBR is a root (ie it has only itself as a parent) and this option is true, the function should
			fail with an indication that the child could not be reassigned because LTBR has no parents. This is
			to explicitly ensure the user is aware the orphans must be reassigned to the default lot.

	assign_LTBR_parent_as_parent_to_non_orphans:
		A bool indicating whether LotMan should attempt to assign LTBR's parents as the new parents to any lots
		that are not orphaned by LTBR's removal. If true, any non-orphans will be updated to have LTBR's parents
		as explicit parents. If false, LTBR will be removed as a parent from the non-orphaned children and no extra
		parents will be added.
		NOTE: If a child of LTBR has only LTBR and itself as a parent, setting this option to false will cause that
			child to become a root.
		NOTE: If LTBR is a root and this option is true, the function should fail with an indication that the child
			could not be reassigned because LTBR has no parents.

	assign_policy_to_children:
		A bool indicating whether LTBR's management policy attributes should be assigned to its children. If true,
		LTBR's children will have their policy attributes overwritten by LTBR's.

	override_policy:
		THIS FEATURE IS NOT YET IMPLEMENTED. A bool indicating whether a lot's stored deletion policy should be
		overwritten by the other options. If true, the lot will be deleted according to other options. If false,
		any of the other options will be superseded by the stored deletion policy

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_remove_lots_recursive(const char *lot_name, char **err_msg);
/**
	DESCRIPTION: A function for deleting a lot and its children, recursively.
		NOTE: Lotman must be called with the correct context set for a lot to be successfully deleted. When deleting a
			lot, the caller must be set to one of the lot's owners.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	lot_name:
		A string indicating the name of the lot to be removed (LTBR)

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_update_lot(const char *lotman_JSON_str, char **err_msg);
/**
	DESCRIPTION: A function for updating parameters of a lot from one value to another, distinct from deleting or
		adding parameters (such as paths or parents). Things that can be updated include owners, parents, paths,
		and management policy attributes.
		NOTE: Lotman must be called with the correct context set for a lot to be successfully updated. When updating
		a lot, the caller must be set to one of the lot's owners.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	lotman_JSON_str:
		A string defining the update object in JSON (see update object specification below).

	err_msg:
		A reference to a char array that can store any error messages.

	Lot Update Object specification:
{   "lot_name":
		REQUIRED: A string indicating the name of the lot.
	"owner":
		OPTIONAL: A string indicating the intended new owner of the lot.
	"parents":
		OPTIONAL: An array of parent update objects, where each parent update object takes the following
		form:
		{"current": "current_parent", "new": "new_parent"}
	"paths":
		OPTIONAL: An array of path update objects, where each path update object takes the following form:
		{"current": "/foo", "new": "/bar", "recursive": true, "exclude": false}
		The "exclude" field is optional. If provided, it updates whether the path is an exclusion.
	"management_policy_attrs":
		OPTIONAL: An object that defines how each/any attribute from the Management Policy Attributes should
		be updated, taking the following form:
		{   "dedicated_GB":
				OPTIONAL: A double indicating the new dedicated_GB value.
			"opportunistic_GB":
				OPTIONAL: A double indicating the new opportunistic_GB value.
			"max_num_objects":
				OPTIONAL: An int64 indicating the new max object count for the lot.
			"expiration_time":
				OPTIONAL: A Unix timestamp in milliseconds indicating the lot's new expiration.
			"deletion_time":
				OPTIONAL: A Unix timestamp in milliseconds indicating the lot's new deletion time.
		}
	"parent_attributions":
		OPTIONAL: An object specifying how each parent's allocation is attributed to this lot.
		Wholesale-replace semantics: any parent omitted from this object receives the equal-split
		remainder of the child's MPAs. When strict_hierarchy is enabled, Axioms 1 and 2 are
		re-validated after the update; failure rolls back the attribution writes.
		Form: {"parent_name": {"dedicated_GB": 2.5, "opportunistic_GB": 1.0, "max_num_objects": 10}, ...}
}
*/

int lotman_rm_parents_from_lot(const char *remove_parents_JSON_str, char **err_msg);
/**
	DESCRIPTION: A function for deleting parents from the lot. This function will not allow all parents
		to be deleted, as lots must have at least one parent (including self-parents).
		NOTE: Lotman must be called with the correct context set for a parent to be removed from a given
		lot. When removing a parent, the caller must be set to one of the lot's owners.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	remove_parents_JSON_str:
		A string defining the JSON object for removing parents (see specification below).

	err_msg:
		A reference to a char array that can store any error messages.

	Parent removal object:
{   "lot_name":
		REQUIRED: A string indicating the name of the lot whose parents are to be removed.
	"parents":
		REQUIRED: An array of strings, indicating which parents are to be removed.
}
*/

int lotman_rm_paths_from_lots(const char *remove_dirs_JSON_str, char **err_msg);
/**
	DESCRIPTION: A function for deleting paths from the lot.
		NOTE: Lotman must be called with the correct context set for a path to be removed from a given
		lot. When removing a path, the caller must be set to one of the lot's owners.
		NOTE: This function does not rely on knowing the name of the lot that will be affected, unlike
		many other functions. Because each path can be bound to only one lot, the function is able to
		determine all required information on its own.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	remove_dirs_JSON_str:
		A string defining the JSON object for removing paths (see specification below).

	err_msg:
		A reference to a char array that can store any error messages.

	Path removal object:
{
	"paths":
		REQUIRED: An array of strings, indicating which paths are to be removed.
}
*/

int lotman_add_to_lot(const char *additions_JSON_str, char **err_msg);
/**
	DESCRIPTION: A function for adding parameters to a lot. Parameters that can be added to a lot
		include parents & paths.
		NOTE: Lotman must be called with the correct context set for parents or paths to be added
		to a given lot. When using this API, the caller must be set to one of the lot's owners.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	additions_JSON_str:
		A string defining the JSON object for adding to the lot (see specification below);

	err_msg:
		A reference to a char array that can store any error messages.

	Additions JSON Object:
{   "lot_name":
		REQUIRED: A string indicating the name of the lot.
	"paths":
		OPTIONAL: An array of path objects with the following form:
		{"path": "/new/path", "recursive": true, "exclude": false}
		The "exclude" field is optional and defaults to false. When true, this path is excluded
		from the lot's tracking rather than included.
	"parents":
		OPTIONAL: An array of strings indicating the new parents to be added to the lot. These
		parents must be existing, valid lot names.
	"parent_attributions":
		OPTIONAL: An object specifying how each parent's allocation is attributed to this lot.
		Processed after `parents`, so newly added parents may appear here. Wholesale-replace
		semantics: any parent omitted from this object receives the equal-split remainder of the
		child's MPAs. When strict_hierarchy is enabled, Axioms 1 and 2 are re-validated.
		Form: {"parent_name": {"dedicated_GB": 2.5, "opportunistic_GB": 1.0, "max_num_objects": 10}, ...}
}
*/

int lotman_lot_exists(const char *lot_name, char **err_msg);
/**
	DESCRIPTION: A function for determining the existence of a lot

	RETURNS: Returns 0 if the lot does not exist, 1 if it does. Any other values indicate an error.

	INPUTS:
	lot_name:
		A string indicating the name of the lot whose existence is to be determined.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_is_root(const char *lot_name, char **err_msg);
/**
	DESCRIPTION: A function for determining whether or not a lot is a root lot.

	RETURNS: Returns 0 if false, 1 if true. Any other values indicate an error.

	INPUTS:
	lot_name:
		A string indicating the lot whose rootness is to be determined.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_owners(const char *lot_name, const bool recursive, char ***output, char **err_msg);
/**
	DESCRIPTION: A function for obtaining owners of a lot. Either the immediate owner can be obtained,
		or the owner of the lot in addition to the owners of the lot's parents.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	lot_name:
		A string indicating the name of the lot whose owners are to be determined.

	recursive:
		A boolean indicating whether only the lot's immediate owner (recursive = false) or all owners
		(recursive = true) should be generated.

	output:
		A reference to a char **, into which the owners of the lot will be placed.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_parent_names(const char *lot_name, const bool recursive, const bool get_self, char ***output,
							char **err_msg);
/**
	DESCRIPTION: A function for obtaining the parents of a lot. Either the immediate parents can be
		obtained, or the parents can be obtained recursively up to the lot's root parent(s).

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	lot_name:
		A string indicating the name of the lot whose parents are to be obtained.

	recursive:
		A boolean indicating whether only the lot's immediate parents (recursive = false) or all parents
		(recursive = true) should be generated.

	get_self:
		A boolean indicating whether self-parenthood should be indicated for the lot being queried against.
		When get_self is set to true, the input lot's own name will be added to the output if it is a self
		parent. Because the lot data structure is a Directed Acyclic Graph (DAG) with the exception of self
		parents, this option allows some DAG algorithms to be run on the data structure.

	output:
		A reference to a char **, into which the parents of the lot will be placed.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	err_msg:
		A reference to a char array that can store any error messages.
*/
int lotman_get_children_names(const char *lot_name, const bool recursive, const bool get_self, char ***output,
							  char **err_msg);
/**
	DESCRIPTION: A function for obtaining the children of a lot. Either immediate children can be
		determined, or children can be generated recursively down to any leaf nodes in the lot
		data structure.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	lot_name:
		A string indicating the name of the lot whose children are to be obtained.

	recursive:
		A boolean indicating whether only the lot's immediate children (recursive = false) or all
		children (recursive = true) should be generated.

	get_self:
		A boolean indicating whether self-parenthood should be indicated for the lot being queried against.
		When get_self is set to true, the input lot's own name will be added to the output if it is a self
		parent (because in this case it is also a self child). Because the lot data structure is a
		Directed Acyclic Graph (DAG) with the exception of self parents, this option allows some DAG
		algorithms to be run on the data structure.

	output:
		A reference to a char **, into which children of the lot will be placed.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_policy_attributes(const char *policy_attributes_JSON_str, char **output, char **err_msg);
/**
	DESCRIPTION: A function for determining a lot's current restricting management policy attributes (MPAs).
		For example, if a lot is created with 10GB of dedicated storage, while a parent of the lot only has
		5GB of dedicated storage, the value 5GB will be returned with an indication of which parent lot
		this restriction comes from.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	policy_attributes_JSON_str:
		A string indicating the JSON object for determining which MPAs should be generated and in what
		manner (see specification below).

	output:
		A character array for storing the results of the query, which will be formatted as a JSON (see
		specification below)

	err_msg:
		A reference to a char array that can store any error messages.

	Policy Attributes Input Json:
{   "lot_name":
		REQUIRED: A string indicating which lot to query against.
	"dedicated_GB":
		OPTIONAL: A boolean indicating whether the value should be generated.
	"opportunistic_GB":
		OPTIONAL: A boolean indicating whether the value should be generated.
	"max_num_objects":
		OPTIONAL: A boolean indicating whether the value should be generated.
	"creation_time":
		OPTIONAL: A boolean indicating whether the value should be generated.
	"expiration_time":
		OPTIONAL: A boolean indicating whether the value should be generated.
	"deletion_time":
		OPTIONAL: A boolean indicating whether the value should be generated.
}

	Policy Attributes Output Json:
		For each attribute passed in the input, the output value will be designated
	as an object indicating the restricting lot name and the restricting value.
	For example, if the input options selected opportunistic_GB and deletion_time,
	the following object would be generated:
{   "opportunistic_GB": {"lot_name": "<restricting_lot>", "value": <value>},
	"deletion_time": {"lot_name", "<restricting_lot>", "value": <value>}
}
*/

int lotman_get_lot_dirs(const char *lot_name, const bool recursive, char **output, char **err_msg);
/**
	DESCRIPTION: A function for getting all paths associated with a given lot. The output can be
		generated to contain only paths tied directly to a lot, or to include the paths tied
		to a lot and all of its children, since these objects may ultimately affect quotas of the
		supplied lot.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	lot_name:
		A string indicating the name of the lot whose paths/dirs/objects should be returned.

	recursive:
		A boolean indicating whether paths tied to children should also be generated
		(recursive = true) or not (recursive = false).

	output:
		A reference to a string array that will contain the generated paths.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_lot_usage(const char *usage_attributes_JSON_str, char **output, char **err_msg);
/**
	DESCRIPTION: A function for determining a lot's usage. Usage queries are capable of
		tracking objects associated directly with a lot, or objects associated with a
		lot and its children. Usage stats that can be tracked using this function include
		dedicated/opportunistic storage, total disk usage, object counts, and GB/objects
		currently being written.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	usage_attributes_JSON_str:
		A string indicating the JSON object for determining what usage metric to generate,
		as well as how the metric should be generated (ie tracking only the input lot, or
		taking parent/child relationships into account -- see specification below).

	output:
		A reference to a character array used to store the output JSON (see specification
		below).

	err_msg:
		A reference to a char array that can store any error messages.

	Usage Attributes Input Json:
{   "lot_name":
		REQUIRED: A string indicating which lot to obtain usage metrics for.
	"dedicated_GB":
		OPTIONAL: A boolean. If included, the output will contain a value for dedicated GB.
		When the boolean is true, the generated value will count children usage against the lot.
	"opportunistic_GB":
		OPTIONAL: A boolean. If included, the output will contain a value for opportunistic GB.
		When the boolean is true, the generated value will count children usage against the lot.
	"total_GB":
		OPTIONAL: A boolean. If included, the output will contain a value for total disk usage.
		When the boolean is true, the generated value will count children usage against the lot.
	"num_objects":
		OPTIONAL: A boolean. If included, the output will contain a value for total object count.
		When the boolean is true, the generated value will count children usage against the lot.
	"GB_being_written":
		OPTIONAL: A boolean. If included, the output will contain a value for GB being written.
		When the boolean is true, the generated value will count children usage against the lot.
	"objects_being_written"
		OPTIONAL: A boolean. If included, the output will contain a value for objects being written.
		When the boolean is true, the generated value will count children usage against the lot.
}

	Usage Attributes Output Json:
		For each specified usage metric in the input object, the resulting output will contain
	information indicating the breakdown of how that metric was calculated. For example,
	if the input object specifies opportunistic_GB: true (indicating children usage should be
	counted in the result) and num_objects: false (indicating children usage should NOT be counted
	in the result), the resulting output JSON will contain:
{   "opportunistic_GB": {"children_contrib": <value 1>, "self_contrib": <value 2>, "total": <value 1 + value 2>},
	"num_objects": {"total": <value>}
}
*/

int lotman_update_lot_usage(const char *update_JSON_str, bool delta_mode, char **err_msg);
/**
	DESCRIPTION: A function for reporting lot usage metrics to LotMan. The function can either interpret
		the input JSON as an absolute accounting of metrics, or as a delta (if deltaMode is set to true).

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	update_JSON_str:
		A string indicating the JSON object that reports usage statistics to LotMan (see specification below).

	delta_mode:
		A boolean indicating whether the update object should be interpreted as an absolute accounting or as a
		delta.

	err_msg:
		A reference to a char array that can store any error messages.

	Update Object Input Json:
{   "lot_name":
		REQUIRED: A string indicating which lot these metrics should be assigned to.
	"self_GB":
		OPTIONAL: A number indicating how many GB are being used by the paths associated directly
		with the lot.
		NOTE: This value should not contain storage accounting for any objects of the lot's children,
		as those metrics are populated internally by LotMan.
	"self_objects":
		OPTIONAL: A number indicating how many objects are being used by the paths associated directly
		with the lot.
		NOTE: This value should not contain storage accounting for any objects of the lot's children,
		as those metrics are populated internally by LotMan.
	"self_GB_being_written":
		OPTIONAL: A number indicating how many GB are being written to the paths associated directly
		with the lot.
		NOTE: This value should not contain storage accounting for any objects of the lot's children,
		as those metrics are populated internally by LotMan.
	"self_objects_being_written":
		OPTIONAL: A number indicating how many objects are being written to the paths associated directly
		with the lot.
		NOTE: This value should not contain storage accounting for any objects of the lot's children,
		as those metrics are populated internally by LotMan.
}
*/

int lotman_update_lot_usage_by_dir(const char *update_JSON_str, bool delta_mode, int64_t query_time, char **err_msg);
/**
	DESCRIPTION: A function for reporting lot usage metrics to LotMan by directory tree. Unlike
		lotman_update_lot_usage, this function only takes a JSON-encoded directory tree, with no
		requirement that the user is aware of which directories belong to which lots. The function
		can either interpret the input JSON as an absolute accounting of metrics, or as a delta
		(if deltaMode is set to true).

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	update_JSON_str:
		A string indicating the JSON object that reports usage statistics to LotMan (see specification below).

	delta_mode:
		A boolean indicating whether the update object should be interpreted as an absolute accounting or as a
		delta.

	err_msg:
		A reference to a char array that can store any error messages.

	Directory Update Json:
		The directory update object is a set of nested JSON objects that encode information about
	usage metrics that LotMan tracks. For LotMan to calculate correct statistics without the
	risk of over or undercounting, care should be taken that the objects are constructed correctly.
	The idea is that each level of the JSON stores information about a path, its size, and object
	count, as well as whether those counts aggregate any statistics from sub directories. For example,
	if the paths '/foo' and '/foo/bar' are both tracked by LotMan and it is reported that '/foo' contains
	10 objects totalling 2GB, an additional object is required so that LotMan can decrement whatever
	is being used by '/foo/bar' from '/foo's statistics. If the additional object reports that '/foo/bar'
	contains 3 objects comprising 0.75GB of space, LotMan will add 7 objects and 1.25GB of usage to '/foo's
	lot, whereas '/foo/bar's lot will be updated with 3 objects and 0.75GB of usage.
[
	{"path":
		REQUIRED: A string indicating the path to the object relative to the outer update JSON without
		a preceding/succeeding file separator.
	"size_GB":
		OPTIONAL: A number indicating how many GB are contained within the directory.
	"num_obj":
		OPTIONAL: A number indicating how many objects are contained within the directory.
	"includes_subdirs":
		REQUIRED: A bool indicating whether 'size_GB' or 'num_obj' are calculated using objects in a
		subdirectory of 'path' that might potentially be tracked by LotMan.
	"subdirs":
		REQUIRED: An array of Directory Update JSON objects that encode information about the usage of
		any of 'path's subdirectories.
	},
	{ <potentially more Directory Update JSON objects> }
]
*/

void lotman_free_string_list(char **str_list);
/**
	DESCRIPTION: A function for freeing char ** arrays allocated internally by LotMan. Use on the output
		wherever a LotMan function takes as input a char ***. Failure to do so will result in memory leaks!

	RETURNS: Void

	INPUTS:
	str_list:
		The array to be freed.
*/

#ifndef LOTMAN_RECLAIM_ERROR
#define LOTMAN_RECLAIM_ERROR -1
#endif
#ifndef LOTMAN_RECLAIM_OK
#define LOTMAN_RECLAIM_OK 0
#endif
#ifndef LOTMAN_RECLAIM_ALREADY_RECLAIMED
#define LOTMAN_RECLAIM_ALREADY_RECLAIMED 1
#endif

int lotman_reclaim_lot(const char *lot_name, int64_t reclaimed_at, const char *reason, char **err_msg);
/**
	DESCRIPTION: Records a reclamation ledger entry for the named lot and every descendant in its
		subtree, marking them as reclaimed by the storage provider. LotMan does NOT delete reclaimed
		lots or modify their MPAs/usage; the reclamation is purely a fact recorded in a `reclamations`
		ledger table. The intent is to let the caller (typically a storage provider's cleanup loop)
		record the moment it is no longer attributing the underlying bytes/objects to the lot, so
		subsequent calls to `lotman_get_lots_past_*` (with include_reclaimed=false) skip the lot,
		capacity and Axiom-2 calculations exclude it, dir-based usage updates suppress its self-write,
		and most mutating APIs reject writes against it. The default lot may not be reclaimed.

		Already-reclaimed lots in the subtree are treated as no-ops, regardless of the existing
		(reclaimed_at, reason) tuple. The existing ledger row is never overwritten. This lets a
		cascade continue when one descendant has already been reclaimed while still recording rows
		for any unreclaimed descendants. If a real write/storage error occurs for any unreclaimed
		lot, the entire batch rolls back.

		Authorization: caller must own the named lot in the same sense as `lotman_remove_lots_recursive`
		(ownership of any of its parents). Authorization to the root authorizes the cascade.

	RETURNS: Returns LOTMAN_RECLAIM_OK (0) when at least one reclamation row was added,
		LOTMAN_RECLAIM_ALREADY_RECLAIMED (1) when every target already had a reclamation row and
		no new row was added, or LOTMAN_RECLAIM_ERROR (-1) on validation, authorization, or storage
		failure.

	INPUTS:
	lot_name:
		The root of the subtree to reclaim. The named lot and every descendant get one ledger
		row each. Must not be the default lot.

	reclaimed_at:
		A Unix timestamp in milliseconds. Must be > 0. May be in the future to schedule a
		reclamation; reclamation-aware filters use `reclaimed_at <= now` so future-dated rows
		do not take effect until their time arrives.

	reason:
		Free-form text recorded alongside the ledger row. May be empty. Not validated.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_lots_past_exp(int64_t query_time, const bool recursive, const bool include_reclaimed, char ***output,
							 char **err_msg);
/**
	DESCRIPTION: A function for determining all lots in the database that are past their expiration
		relative to a caller-supplied cutoff. The function can determine which lots meet this criteria
		either by looking at the expiration directly associated with each lot, or recursively by
		looking at the most restricting expiration in each lot's parent tree.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	query_time:
		A Unix timestamp in milliseconds used as the expiration cutoff. A lot is included iff its
		`expiration_time` is non-zero AND `expiration_time <= query_time`. The same value is used
		for reclamation evaluation when include_reclaimed=false: a lot is treated as reclaimed iff
		its reclamation row's `reclaimed_at <= query_time`. Pass wall-clock now() for the
		historical "as of now" semantics; pass a future timestamp to preview which lots will be
		expired by then.

	recursive:
		A boolean indicating whether the output should contain only lots whose personal expiration is
		passed (recursive = false) or it should contain all lots who may also have an expired parent
		(recursive = true).

	include_reclaimed:
		A boolean indicating whether reclaimed lots (rows in the `reclamations` ledger whose
		`reclaimed_at <= query_time`) should be included in the result. When false (the typical use
		case for cleanup loops), reclaimed lots are filtered out so the loop will not repeatedly
		process lots that the storage provider has already cleaned up.

	output:
		A reference to a char ** for storing an array of expired lot names.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	err_msg:
		A reference to a char array that can store any error messages.

	NOTE: Sentinel (non-expiring, all-zero timestamp) lots are never returned regardless of
		query_time, matching the rest of LotMan's sentinel handling.
*/

int lotman_get_lots_past_del(int64_t query_time, const bool recursive, const bool include_reclaimed, char ***output,
							 char **err_msg);
/**
	DESCRIPTION: A function for determining all lots in the database that are past their deletion time
		relative to a caller-supplied cutoff. The function can determine which lots meet this criteria
		either by looking at the deletion time directly associated with each lot, or recursively by
		looking at the most restricting deletion time in each lot's parent tree.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	query_time:
		A Unix timestamp in milliseconds used as the deletion cutoff. A lot is included iff its
		`deletion_time` is non-zero AND `deletion_time <= query_time`. The same value is used for
		reclamation evaluation when include_reclaimed=false. Pass wall-clock now() for the
		historical "as of now" semantics; pass a future timestamp to preview which lots will be
		past their deletion time by then.

	recursive:
		A boolean indicating whether the output should contain only lots whose personal deletion time is
		passed (recursive = false) or it should contain all lots who may also have a parent passed its
		deletion time (recursive = true).

	include_reclaimed:
		A boolean indicating whether reclaimed lots (rows in the `reclamations` ledger whose
		`reclaimed_at <= query_time`) should be included in the result. Cleanup loops should typically
		pass false so they do not repeatedly process lots that have already been reclaimed.

	output:
		A reference to a char ** for storing an array of lots passed their deletion time.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	err_msg:
		A reference to a char array that can store any error messages.

	NOTE: Sentinel (non-expiring, all-zero timestamp) lots are never returned regardless of
		query_time.
*/

int lotman_get_lots_past_opp(const bool recursive_quota, const bool recursive_children, const bool include_reclaimed,
							 char ***output, const bool hierarchical, char **err_msg);
/**
	DESCRIPTION: A function for determining all lots in the database that are past their opportunistic storage.
		The function can determine which lots meet this criteria either by looking at the opportunistic storage
		directly associated with each lot, or recursively by looking at the most restricting opportunistic
		storage attribute in each lot's parent tree.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS (in declaration order):
	recursive_quota:
		A boolean indicating whether quotas should be treated recursively, ie whether the usage of a lot's children
		should be counted against its own usage (recursive_quota = true) or whether only a lot's personal usage
		should be counted (recursive_quota = false).

	recursive_children:
		A boolean indicating whether the children of an offending lot should also be returned. In some cases, it may
		be useful to also treat these children as offending lots.
		NOTE: The children generated when recursive_children is true will include all recursive children of the lot,
		not just immediate children.

	include_reclaimed:
		A boolean indicating whether reclaimed lots (rows in the `reclamations` ledger whose
		`reclaimed_at <= now`) should be included in the result. Cleanup loops should typically
		pass false to avoid repeatedly processing lots that have already been reclaimed.
		NOTE: When hierarchical = true, reclaimed parents are excluded from the result
		unconditionally (regardless of include_reclaimed) because their storage has been
		released to the default lot and they cannot meaningfully be "past" their own quota.
		include_reclaimed only governs post-filtering on the non-hierarchical path.

	output:
		A reference to a char ** for storing an array of lots passed their opportunistic storage quota.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	hierarchical:
		A boolean indicating whether the query should use hierarchy-aware adjusted usage.
		When true, a parent's usage is adjusted by adding any overage from its children
		(usage exceeding the child's own threshold). Results are returned depth-ordered
		(deepest/leaf lots first). When true, recursive_quota and recursive_children
		are not used by the hierarchical query path.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_lots_past_ded(const bool recursive_quota, const bool recursive_children, const bool include_reclaimed,
							 char ***output, const bool hierarchical, char **err_msg);
/**
	DESCRIPTION: A function for determining all lots in the database that are past their dedicated storage.
		The function can determine which lots meet this criteria either by looking at the dedicated storage
		directly associated with each lot, or recursively by looking at the most restricting dedicated
		storage attribute in each lot's parent tree.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS (in declaration order):
	recursive_quota:
		A boolean indicating whether quotas should be treated recursively, ie whether the usage of a lot's children
		should be counted against its own usage (recursive_quota = true) or whether only a lot's personal usage
		should be counted (recursive_quota = false).

	recursive_children:
		A boolean indicating whether the children of an offending lot should also be returned. In some cases, it may
		be useful to also treat these children as offending lots.
		NOTE: The children generated when recursive_children is true will include all recursive children of the lot,
		not just immediate children.

	include_reclaimed:
		A boolean indicating whether reclaimed lots (rows in the `reclamations` ledger whose
		`reclaimed_at <= now`) should be included in the result. Cleanup loops should typically
		pass false to avoid repeatedly processing lots that have already been reclaimed.
		NOTE: When hierarchical = true, reclaimed parents are excluded from the result
		unconditionally (regardless of include_reclaimed) because their storage has been
		released to the default lot and they cannot meaningfully be "past" their own quota.
		include_reclaimed only governs post-filtering on the non-hierarchical path.

	output:
		A reference to a char ** for storing an array of lots passed their dedicated storage quota.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	hierarchical:
		A boolean indicating whether the query should use hierarchy-aware adjusted usage.
		When true, a parent's usage is adjusted by adding any overage from its children
		(usage exceeding the child's own threshold). Results are returned depth-ordered
		(deepest/leaf lots first). When true, recursive_quota and recursive_children
		are not used by the hierarchical query path.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_lots_past_obj(const bool recursive_quota, const bool recursive_children, const bool include_reclaimed,
							 char ***output, const bool hierarchical, char **err_msg);
/**
	DESCRIPTION: A function for determining all lots in the database that are past their object storage quota.
		The function can determine which lots meet this criteria either by looking at the object storage quota
		directly associated with each lot, or recursively by looking at the most restricting object
		storage attribute in each lot's parent tree.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS (in declaration order):
	recursive_quota:
		A boolean indicating whether quotas should be treated recursively, ie whether the usage of a lot's children
		should be counted against its own usage (recursive_quota = true) or whether only a lot's personal usage
		should be counted (recursive_quota = false).

	recursive_children:
		A boolean indicating whether the children of an offending lot should also be returned. In some cases, it may
		be useful to also treat these children as offending lots.
		NOTE: The children generated when recursive_children is true will include all recursive children of the lot,
		not just immediate children.

	include_reclaimed:
		A boolean indicating whether reclaimed lots (rows in the `reclamations` ledger whose
		`reclaimed_at <= now`) should be included in the result. Cleanup loops should typically
		pass false to avoid repeatedly processing lots that have already been reclaimed.
		NOTE: When hierarchical = true, reclaimed parents are excluded from the result
		unconditionally (regardless of include_reclaimed) because their storage has been
		released to the default lot and they cannot meaningfully be "past" their own quota.
		include_reclaimed only governs post-filtering on the non-hierarchical path.

	output:
		A reference to a char ** for storing an array of lots passed their max object count quota.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	hierarchical:
		A boolean indicating whether the query should use hierarchy-aware adjusted usage.
		When true, a parent's usage is adjusted by adding any overage from its children
		(usage exceeding the child's own threshold). Results are returned depth-ordered
		(deepest/leaf lots first). When true, recursive_quota and recursive_children
		are not used by the hierarchical query path.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_available_capacity(const char *parent_lot_name, int64_t start_time, int64_t end_time, char **output,
								  char **err_msg);
/**
	DESCRIPTION: Compute available and peak capacity under a parent lot during a time window.
		Sums each child's parent_attributions over the supplied window using a sweep-line
		algorithm that accounts for overlapping active intervals, then subtracts the peak
		concurrent usage from the parent's MPAs.

		WARNING: This is an *advisory* query, not a reservation mechanism. Reservation
		enforcement is performed atomically by Axiom 2 inside the lot-creation transaction
		when strict_hierarchy is enabled, so another caller may legitimately claim capacity
		between this query and the subsequent create.

		Reclaimed children (rows in the `reclamations` ledger whose `reclaimed_at <= now`) are
		silently excluded from the sweep -- their attributed capacity is treated as freed and
		no longer counted against the parent.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	parent_lot_name:
		The name of the parent lot whose capacity should be queried.

	start_time:
		Beginning of the query window, as a Unix timestamp in milliseconds (inclusive).

	end_time:
		End of the query window, as a Unix timestamp in milliseconds (exclusive). Children
		whose active intervals overlap [start_time, end_time) are clipped to that window
		before being summed.

	output:
		A reference to a char * for storing the result, formatted as a JSON object (see
		specification below).
		NOTE: The caller owns the returned string and must free() it.

	err_msg:
		A reference to a char array that can store any error messages.

	Output JSON Specification:
{   "available_dedicated_GB":     <number>,  // parent dedicated_GB minus peak concurrent attributed dedicated_GB
	"available_opportunistic_GB": <number>,  // analogous for opportunistic_GB
	"available_max_num_objects":  <int64>,   // analogous for max_num_objects
	"available_total_GB":         <number>,  // (parent dedicated_GB + opportunistic_GB) minus peak (ded+opp)
	"peak_dedicated_GB":          <number>,
	"peak_opportunistic_GB":      <number>,
	"peak_max_num_objects":       <int64>,
	"peak_total_GB":              <number>   // peak (ded+opp) at any single instant in the window
}
*/

int lotman_list_all_lots(char ***output, char **err_msg);
/**
	DESCRIPTION: A function for listing all lots in the LotMan database.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	output:
		A reference to a char ** for storing the output.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_lot_as_json(const char *lot_name, const bool recursive, char **output, char **err_msg);
/**
	DESCRIPTION: A function for getting information about a single lot in JSON format. The function
		can either generate information about the input lot only, or it can get the most restricting
		attributes of the lot based on parent/child relationships.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	lot_name:
		A string indicating which lot should be queried for.

	recursive:
		A bool indicating whether the reported attributes should come only from what is stored in the
		database about the lot itself (recursive = false), or whether LotMan should calculate the
		restricting attributes for the lot as determined by its parent/child relationships
		(recursive = false).

	output:
		A reference to a char array that can store the encoded JSON string for the lot (see specification
		below).

	err_msg:
		A reference to a char array that can store any error messages.

	Output JSON Specification:
{   "lot_name":
		A string indicating the lot's name.
	"owners":
		An array of strings indicating the lot's owner(s). If recursive if false, only the lot's direct
		owner will be returned, otherwise all parent owners will be included.
	"parents":
		An array of strings indicating the lot's parents.
	"children":
		An array of strings indicating the lot's children.
	"paths":
		An array of JSON objects encoding information about each path associated with the lot, including
		both included and excluded paths. Each path object has the following format:
		{"path": "/a/path/", "lot_name": <name of lot>, "recursive": <bool>, "exclude": <bool>}
		When "exclude" is true, this path is excluded from the lot's tracking. If recursive is false in the
		API call, the "lot_name" field is omitted as it is assumed to be the supplied input lot.
	"management_policy_attrs":
		A JSON object containing information about the lot's MPAs, as determined by accounting
for the 'recursive' flag. When recursive is true, each MPA will contain a JSON object with the following format:
		{"lot_name": "<name of restricting lot>", "value": <restricting value>}
	"usage":
		A JSON object containing each of the lot's usage metrics, as determined by accounting for the 'recursive'
		flag. When recursive is true, each usage metric will contain a JSON object with the following format:
		{"children_contrib": <value>,"self_contrib": <value>}
	"parent_attributions":
		A JSON object describing how the lot's MPAs are attributed across each non-self parent, in the same shape
		accepted by lotman_add_lot. The form is:
		{"<parent_name>": {"dedicated_GB": <value>, "opportunistic_GB": <value>, "max_num_objects": <int>}}
		Values are absolute MPA shares (not fractions), so a create-then-read round-trip is symmetric. Unbounded
		child axes (-1 sentinel) propagate to each parent as -1. For self-parent-only lots (i.e. lots with no
		non-self parents), this field is an empty object.
	"reclamation":
		OPTIONAL. Present only when a reclamation ledger row exists for the lot. A JSON object of the
		form {"reclaimed_at": <int64 ms>, "reason": <string>}. When `reclaimed_at <= now`, the lot is
		effectively reclaimed; when `reclaimed_at > now`, the row represents a scheduled reclamation
		that has not yet taken effect.
}
*/

int lotman_get_lots_from_dir(const char *dir, const bool recursive, int64_t query_time, char ***output, char **err_msg);
/**
	DESCRIPTION: A function for getting any lots associated with the supplied path. The function can
		return either solely the lot tracking the path, or any parent lots who might also be affected
		by the path.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	dir:
		A string indicating the path to be queried for

	recursive:
		A boolean indicating whether only the lot tracking the path should be returned (recursive = false),
		or whether all parent lots should also be returned (recursive = true).

	query_time:
		A Unix timestamp in milliseconds used to filter active path/lot rows: a lot is considered active
		when its MPA window contains `query_time` and any reclamation row for it has `reclaimed_at >
		query_time`. Passing the current wall-clock time yields the live-as-of-now view; reclaimed lots
		are therefore filtered out.

	output:
		A reference to a char ** for storing the output array.
		NOTE: Requires the use of lotman_free_string_list to free the memory allocated for this array.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_lots_for_path(const char *path, bool recursive, int64_t time_lo_ms, int64_t time_hi_ms,
							 bool include_reclaimed, char **output, char **err_msg);
/**
	DESCRIPTION: Window-aware variant of lotman_get_lots_from_dir. Returns the union of every lot
		that "wins" the longest-prefix path-resolution contest at any instant in the half-open
		window [time_lo_ms, time_hi_ms). Two lots may both be returned when each owns the path
		during disjoint sub-intervals of the window (for example a sublot that takes over from
		its parent partway through the window). The dynamic-ownership rules from
		lotman_get_lots_from_dir apply unchanged: same lot, longer included path wins; an
		excluded path row strictly longer than a candidate inclusion suppresses it; the default
		lot is appended iff some instant in the window has no candidate active.

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	path:
		A string indicating the path to be queried for. Trailing slashes are normalized internally;
		matching is performed against the lots' stored path rows.

	recursive:
		A boolean indicating whether only the directly-resolved owning lot(s) should be returned
		(recursive = false), or whether all parent lots of each winner should also be returned
		(recursive = true). Matches the meaning of the recursive argument on lotman_get_lots_from_dir.

	time_lo_ms:
		Beginning of the query window, as a Unix timestamp in milliseconds (inclusive).

	time_hi_ms:
		End of the query window, as a Unix timestamp in milliseconds (exclusive). A lot's
		[creation_time, expiration_time) interval is considered to overlap the window iff
		creation_time < time_hi_ms AND expiration_time > time_lo_ms. Sentinel (all-zero
		timestamp) lots are treated as always-live and overlap every window. Must be strictly
		greater than time_lo_ms; otherwise the function fails with err_msg set.

	include_reclaimed:
		A boolean indicating how reclamation rows interact with the window. When true, reclaimed
		lots are included as if no reclamation row existed. When false, lots whose reclamation
		row has reclaimed_at <= time_lo_ms are dropped entirely (their storage has been released
		for the entirety of the window), while lots reclaimed mid-window have their effective
		active interval clipped to [..., reclaimed_at) before the longest-prefix sweep — they
		may still be returned iff their pre-reclamation interval makes them a winner. When
		recursive=true, ancestors are filtered under the same rule: an ancestor is suppressed
		only when it is reclaimed for the entirety of the window (reclaimed_at <= time_lo_ms).

	output:
		A reference to a char * for storing the result, formatted as a JSON array string. Each
		element of the array is a full lot object identical in shape to a single
		lotman_get_lot_as_json(lot_name, recursive=false) result; see that API's output JSON
		specification for the field set. The result always contains at least one element: when
		no lot wins anywhere in the window, the default lot is appended (matching
		lotman_get_lots_from_dir's fallback behavior).
		NOTE: The caller owns the returned string and must free() it.

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_set_context_str(const char *key, const char *value, char **err_msg);
/**
	DESCRIPTION: Provides access to setting various configuration/context values in LotMan

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	key:
		A string indicating which context key is being set. Currently, possible context keys are the "caller"
		(ie identity of who's calling a LotMan function, needed in some cases when determining whether a
		particular call should be allowed) and "lot_home", which is used for setting the location of the
		generated LotMan SQLite database.

	value:
		The intended value to be assumed by whichever key is provided

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_context_str(const char *key, char **output, char **err_msg);
/**
	DESCRIPTION: Provides access for getting various configuration/context values in LotMan

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	key:
		A string indicating which context key is being set. Currently, possible context keys are the "caller"
		(ie identity of who's calling a LotMan function, needed in some cases when determining whether a
		particular call should be allowed) and "lot_home", which is used for setting the location of the
		generated LotMan SQLite database.

	output:
		A buffer for storing the output from the operation

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_set_context_int(const char *key, const int value, char **err_msg);
/**
	DESCRIPTION: Provides access for setting various configuration/context values in LotMan

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	key:
		A string indicating which context key is being set.

	value:
		The intended value to be assumed by whichever key is provided

	err_msg:
		A reference to a char array that can store any error messages.
*/

int lotman_get_context_int(const char *key, int *output, char **err_msg);
/**
	DESCRIPTION: Provides access for getting various configuration/context values in LotMan

	RETURNS: Returns 0 on success. Any other values indicate an error.

	INPUTS:
	key:
		A string indicating which context key is being set. Currently valid is "db_timeout", a
		max value in milliseconds that the database should wait when trying to establish a lock
		on the database. Can be tuned in multiprocess environments to eliminate any potential
		sqlite error no. 5 complaints (SQLITE_BUSY)

	output:
		A buffer for storing the output from the operation

	err_msg:
		A reference to a char array that can store any error messages.
*/

// int lotman_get_matching_lots(const char *criteria_JSON, char ***output, char **err_msg);
// int lotman_check_db_health(char **err_msg); // Should eventually check that data structure conforms to expectations.
// If there's a cycle or a non-self-parent root, something is wrong

#ifdef __cplusplus
}
#endif

#endif // LOTMAN_H
