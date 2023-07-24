#include "tyche_api.h"
#include "tyche_capabilities.h"
#include "tyche_capabilities_types.h"
#define TYCHE_DEBUG 1
#include "common.h"

// ———————————————————————————————— Globals ————————————————————————————————— //

domain_t local_domain;

// ———————————————————————— Private helper functions ———————————————————————— //

void local_memcpy(void *dest, void *src, unsigned long n) {
  unsigned long i = 0;
  char *csrc = (char *)src;
  char *cdest = (char *)dest;
  for (i = 0; i < n; i++) {
    cdest[i] = csrc[i];
  }
}

void local_memset(void *dest, unsigned long n) {
  unsigned long i = 0;
  char *cdest = (char *)dest;
  for (i = 0; i < n; i++) {
    cdest[i] = 0;
  }
}

child_domain_t* find_child(domain_id_t id)
{
  child_domain_t *child = NULL;
  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }
  return child;
}

int has_access_rights(memory_access_right_t orig, memory_access_right_t dest)
{
  return (orig & dest) == dest;
}

// —————————————————————————————— Public APIs ——————————————————————————————— //

int init(capa_alloc_t allocator, capa_dealloc_t deallocator) {
  capa_index_t next = 0;
  if (allocator == 0 || deallocator == 0) {
    goto fail;
  }
  // Set the local domain's functions.
  local_domain.alloc = allocator;
  local_domain.dealloc = deallocator;
  dll_init_list(&(local_domain.capabilities));
  dll_init_list(&(local_domain.children));

  // Start enumerating the domain's capabilities.
  while (1) {
    capability_t tmp_capa;
    capability_t *capa = NULL;
    if (enumerate_capa(next, &next, &tmp_capa) != SUCCESS || next == 0) {
      // Failed to read or no more capa
      break;
    }

    capa = (capability_t *)(local_domain.alloc(sizeof(capability_t)));
    if (capa == NULL) {
      ERROR("Unable to allocate a capability!\n");
      goto failure;
    }
    // Copy the capability into the dynamically allocated one.
    local_memcpy(capa, &tmp_capa, sizeof(capability_t));
    dll_init_elem(capa, list);

    // Add the capability to the list.
    dll_add(&(local_domain.capabilities), capa, list);
  }

  DEBUG("success");
  return SUCCESS;
failure:
  while (!dll_is_empty(&local_domain.capabilities)) {
    capability_t *capa = local_domain.capabilities.head;
    dll_remove(&(local_domain.capabilities), capa, list);
    local_domain.dealloc((void *)capa);
  }
fail:
  return FAILURE;
}

int create_domain(domain_id_t *id) {
  capa_index_t child_idx = -1;
  capability_t *child_capa = NULL;
  child_domain_t *child = NULL;

  DEBUG("start");
  // Initialization was not performed correctly.
  if (id == NULL) {
    ERROR("id null.");
    goto fail;
  }

  // Perform allocations.
  child = (child_domain_t *)local_domain.alloc(sizeof(child_domain_t));
  if (child == NULL) {
    ERROR("Failed to allocate child.");
    goto fail;
  }
  child_capa = (capability_t *)local_domain.alloc(sizeof(capability_t));
  if (child_capa == NULL) {
    ERROR("Failed to allocate child_capa.");
    goto fail_child;
  }

  // Create the domain.
  if (tyche_create_domain(&child_idx) != SUCCESS) {
    ERROR("Failed to create domain.");
    goto fail_child_capa;
  }

  // Populate the capability.
  if (enumerate_capa(child_idx, NULL, child_capa) != SUCCESS) {
    ERROR("Failed to enumerate the newly created child.");
    goto fail_child_capa;
  }

  // Check that the child capa is a management one.
  if (child_capa->capa_type != Management ||
      child_capa->info.management.status != Unsealed) {
    ERROR("The created domain capa is invalid: type: 0x%x status 0x%x",
        child_capa->capa_type,
        child_capa->info.management.status);
    goto fail_child_capa;
  }

  // Initialize the other capa fields.
  child_capa->parent = NULL;
  child_capa->left = NULL;
  child_capa->right = NULL;
  dll_init_elem(child_capa, list); 

  // Initialize the child domain.
  child->id = local_domain.id_counter++;
  child->management = child_capa;
  dll_init_list(&(child->revocations));
  dll_init_list(&(child->transitions));
  dll_init_elem(child, list);

  // Add the child to the local_domain.
  dll_add(&(local_domain.children), child, list);

  // All done!
  *id = child->id;
  DEBUG("Success");
  return SUCCESS;

  // Failure paths.
fail_child_capa:
  local_domain.dealloc(child_capa);
fail_child:
  local_domain.dealloc(child);
fail:
  return FAILURE;
}

int set_domain_traps(domain_id_t id, usize traps)
{
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found");
    goto failure;
  }
  if (tyche_set_traps(child->management->local_id, traps) != SUCCESS) {
    ERROR("Unable to set the traps with a vmcall.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int set_domain_cores(domain_id_t id, usize cores)
{
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found");
    goto failure;
  }
  if (tyche_set_cores(child->management->local_id, cores) != SUCCESS) {
    ERROR("Unable to set the cores with a vmcall.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int set_domain_perm(domain_id_t id, usize perm)
{
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found");
    goto failure;
  }
  if (tyche_set_perm(child->management->local_id, perm) != SUCCESS) {
    ERROR("Unable to set the perm with a vmcall.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int set_domain_switch(domain_id_t id, usize swtype)
{
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found");
    goto failure;
  }
  if (tyche_set_switch(child->management->local_id, swtype) != SUCCESS) {
    ERROR("Unable to set the switch with a vmcall.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}


int set_domain_entry_on_core(
    domain_id_t id,
    usize core,
    usize cr3,
    usize rip,
    usize rsp)
{
  child_domain_t *child = find_child(id);
  if (child == NULL) {
    ERROR("Child not found");
    goto failure;
  }
  if (tyche_set_entry(child->management->local_id, core, cr3, rip, rsp) != SUCCESS) {
    ERROR("Unable to set the entry point with a vmcall.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int seal_domain(domain_id_t id) {
  child_domain_t *child = NULL;
  capability_t *transition = NULL;
  transition_t *trans_wrapper = NULL;

  DEBUG("start");
  // Find the target domain.
  child = find_child(id); 

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("Child not found.");
    goto failure;
  }

  transition = (capability_t *)local_domain.alloc(sizeof(capability_t));
  if (transition == NULL) {
    ERROR("Could not allocate transition capa.");
    goto failure;
  }

  trans_wrapper = (transition_t *)local_domain.alloc(sizeof(transition_t));
  if (trans_wrapper == NULL) {
    ERROR("Unable to allocate transition_t wrapper");
    goto failure_transition;
  }

  // Create the transfer.
  if (child->management == NULL) {
    ERROR("The child's management is null");
    goto failure_dealloc;
  }
  if (child->management->capa_type != Management ||
      child->management->info.management.status != Unsealed ) {
    ERROR("we do not have a valid unsealed capa.");
    ERROR("management capa: type: 0x%x  -- status 0x%x",
        child->management->info.management.status,
        child->management->info.management.status);
    goto failure_dealloc;
  }

  if (tyche_seal(&(transition->local_id), child->management->local_id) != SUCCESS) {
    ERROR("Unable to create a channel.");
    goto failure_dealloc;
  }

  // Enumerate the transition capability.
  if (enumerate_capa(transition->local_id, NULL, transition) != SUCCESS) {
    ERROR("Unable to read the transition capability.");
    goto failure_dealloc;
  }

  // Update the management capability.
  if (enumerate_capa(child->management->local_id, NULL, child->management) != SUCCESS) {
    ERROR("Unable to update the management capa.");
    goto failure_dealloc;
  }

  // Initialize the transition wrapper.
  trans_wrapper->transition = transition;
  trans_wrapper->lock = TRANSITION_UNLOCKED;
  dll_init_elem(trans_wrapper, list);

  // Add the transition wrapper to the child.
  dll_add(&(child->transitions), trans_wrapper, list);

  // All done !
  DEBUG("Success");
  return SUCCESS;
failure_dealloc:
  local_domain.dealloc(trans_wrapper);
failure_transition:
  local_domain.dealloc(transition);
failure:
  return FAILURE;
}

int segment_region_capa(
    capability_t *capa,
    capability_t **left,
    capability_t **right,
    usize start1,
    usize end1,
    usize prot1,
    usize start2,
    usize end2,
    usize prot2) {
  if (left == NULL || right == NULL || capa == NULL) {
    goto failure;
  }

  // Attempt to allocate left and right.
  *left = (capability_t *)local_domain.alloc(sizeof(capability_t));
  if (*left == NULL) {
    ERROR("Left alloc failed.");
    goto failure;
  }
  *right = (capability_t *)local_domain.alloc(sizeof(capability_t));
  if (*right == NULL) {
    ERROR("Right alloc failed.");
    goto fail_left;
  }

  // Call duplicate.
  if (tyche_segment_region(
        capa->local_id,
        &((*left)->local_id),
        &((*right)->local_id),
        start1, end1, prot1,
        start2, end2, prot2) != SUCCESS) {
    ERROR("Duplicate rejected.");
    goto fail_right;
  }

  // Update the capability.
  if (enumerate_capa(capa->local_id, NULL, capa) != SUCCESS) {
    ERROR("We failed to enumerate the root of a duplicate!");
    goto fail_right;
  }
  capa->left = *left;
  capa->right = *right;

  // Initialize the left.
  if (enumerate_capa((*left)->local_id, NULL, *left) != SUCCESS) {
    ERROR("We failed to enumerate the left of duplicate!");
    goto fail_right;
  }
  dll_init_elem((*left), list);
  dll_add(&(local_domain.capabilities), (*left), list);
  (*left)->parent = capa;
  (*left)->left = NULL;
  (*left)->right = NULL;

  // Initialize the right.
  if (enumerate_capa((*right)->local_id, NULL, (*right)) != SUCCESS) {
    ERROR("We failed to enumerate the right of duplicate!");
    goto fail_right;
  }
  dll_init_elem((*right), list);
  dll_add(&(local_domain.capabilities), (*right), list);
  (*right)->parent = capa;
  (*right)->left = NULL;
  (*right)->right = NULL;

  // All done!
  return SUCCESS;

  // Failure paths.
fail_right:
  local_domain.dealloc(*right);
fail_left:
  local_domain.dealloc(*left);
failure:
  return FAILURE;
}


/* This function takes a capability and performs a split such that:
*       capa
*       / \
*   NULL    copy(capa)
* This is used to facilitate revocation in share and grant.
* It returns the copy(capa) and makes sure to update capa to be a revocation.
* The returned value is not part of any list and can be freed with local_domain.dealloc.
*/
static capability_t* trick_segment_null_copy(capability_t* capa)
{
  capability_t *left = NULL, *right = NULL;
  if (capa == NULL) {
    ERROR("Provided capability is NULL.");
    goto failure;
  }

  // This function only makes sense on region capabilities that are active.
  if (capa->capa_type != Region ||
      (capa->info.region.flags & MEM_ACTIVE) != MEM_ACTIVE) {
    ERROR("Wrong type of capability");
    goto failure;
  }

  // Perform the split.
  if (segment_region_capa(
        capa, &left, &right,
        // This is NULL
        capa->info.region.start, capa->info.region.start, capa->info.region.flags >> 2,
        // This is copy(capa)
        capa->info.region.start, capa->info.region.end, capa->info.region.flags >> 2
        ) != SUCCESS) {
    ERROR("Unable to perform the duplicate");
    goto failure;
  }

  // Delete the left.
  if (left == NULL) {
    ERROR("Left is null.");
    goto failure;
  }
  dll_remove(&(local_domain.capabilities), left, list);
  capa->left = NULL;
  local_domain.dealloc(left);
  left = NULL;

  // Remove the right.
  dll_remove(&(local_domain.capabilities), right, list);
  capa->right = NULL;

  // We're done.
  right->parent = NULL;
  right->left = NULL;
  right->right = NULL;
  return right;
failure:
  return NULL;
}

// TODO: for the moment only handle the case where the region is fully contained
// within one capability.
int carve_region(domain_id_t id, paddr_t start, paddr_t end,
                 memory_access_right_t access, int is_shared) {
  child_domain_t *child = NULL;
  capability_t *capa = NULL;

  DEBUG("[grant_region] start");
  // Quick checks.
  if (start >= end) {
    ERROR("Start is greater or equal to end.\n");
    goto failure;
  }

  // Find the target domain.
  child = find_child(id); 

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("Child not found.");
    goto failure;
  }

  // Now attempt to find the capability.
  dll_foreach(&(local_domain.capabilities), capa, list) {
    if (capa->capa_type != Region || (capa->info.region.flags & MEM_ACTIVE) == 0) {
      continue;
    }
    if ((dll_contains(
            capa->info.region.start,
            capa->info.region.end, start)) &&
        (capa->info.region.start <= end && capa->info.region.end >= end)
        && has_access_rights(capa->info.region.flags, access)) {
      // Found the capability.
      break;
    }
  }

  // We were not able to find the capability.
  if (capa == NULL) {
    LOG("The access rights we want: %x", access);
    ERROR("Unable to find the containing capa.");
    goto failure;
  }

  // The region is in the middle, requires two splits.
  if (capa->info.region.start < start && capa->info.region.end > end) {
    // Middle case.
    // capa: [s.......................e]
    // grant:     [m.....me]
    // Duplicate such that we have [s..m] [m..me..e]
    // And then update capa to be equal to the right
    capability_t *left = NULL, *right = NULL;
    if (segment_region_capa(
          capa, &left, &right,
          capa->info.region.start, start, capa->info.region.flags >> 2,
          start, capa->info.region.end, capa->info.region.flags >> 2) != SUCCESS) {
      ERROR("Middle case duplicate failed.");
      goto failure;
    }
    // Update the capa to point to the right.
    capa = right;
  }

  // Requires a duplicate.
  if ((capa->info.region.start == start && capa->info.region.end > end) ||
      (capa->info.region.start < start && capa->info.region.end == end)) {
    paddr_t s = 0, m = 0, e = 0;
    capability_t *left = NULL, *right = NULL;
    memory_access_right_t ops_left = 0, ops_right = 0;
    capability_t **to_grant = NULL;

    if (capa->info.region.start == start && capa->info.region.end > end) {
      // Left case.
      // capa: [s ............e].
      // grant:[s.......m].
      // duplicate: [s..m] - [m..e]
      // Grant the first portion.
      s = capa->info.region.start;
      m = end;
      e = capa->info.region.end;
      to_grant = &left;
      ops_left = access;
      ops_right = capa->info.region.flags;
    } else {
      // Right case.
      // capa: [s ............e].
      // grant:      [m.......e].
      // duplicate: [s..m] - [m..e]
      // Grant the second portion.
      s = capa->info.region.start;
      m = start;
      e = capa->info.region.end;
      to_grant = &right;
      ops_left = capa->info.region.flags;
      ops_right = access;
    }

    // Do the duplicate.
    if (segment_region_capa(capa, &left, &right,
          s, m, ops_left >> 2,
          m, e, ops_right >> 2) != SUCCESS) {
      ERROR("Left or right duplicate case failed.");
      goto failure;
    }

    // Now just update the capa to grant.
    capa = *to_grant;
  }

  // At this point, capa should be a perfect overlap.
  if (capa == NULL ||
      !(capa->info.region.start == start && capa->info.region.end == end)) {
    goto failure;
  }

  // If we have a share, we want to keep access to the region.
  if (is_shared) {
    capability_t* left_copy = NULL, *right_copy = NULL, *to_send = capa;  
    if (segment_region_capa(
          to_send, &left_copy, &right_copy, 
          to_send->info.region.start, to_send->info.region.end, to_send->info.region.flags >> 2,
          to_send->info.region.start, to_send->info.region.end, to_send->info.region.flags >> 2) != SUCCESS) {
      ERROR("For shared, unable to duplicate capability.");
      goto failure;
    }
    capa = right_copy;
  }

  // One last duplicate to have a revocation {NULL, to_send}.
  do {
    capability_t *to_send = trick_segment_null_copy(capa);
    if (to_send == NULL) {
      ERROR("To send is null.");
      goto failure;
    }

    // Check we have a revocation capa.
    if (capa->capa_type != Region || (capa->info.region.flags & MEM_ACTIVE) != 0) {
      ERROR("This should be a revocation capability.");
      goto failure;
    }

    // Send the capa to the target.
    if (tyche_send(child->management->local_id, to_send->local_id) != SUCCESS) {
      ERROR("Unable to send the capability!");
      goto failure;
    } 

    // Cleanup to send.
    local_domain.dealloc(to_send);
  } while(0);

  // Remove it from the capabilities and put it in the revocation list..
  dll_remove(&(local_domain.capabilities), capa, list);
  dll_add(&(child->revocations), capa, list);

  // We are done!
  DEBUG("Success");
  return SUCCESS;
failure:
  return FAILURE;
}

int grant_region(domain_id_t id, paddr_t start, paddr_t end,
                 memory_access_right_t access)
{
  return carve_region(id, start, end, access, 0);
} 

int share_region(domain_id_t id, paddr_t start, paddr_t end,
                 memory_access_right_t access) {
  return carve_region(id, start, end, access, 1); 
}

// TODO for now we only handle exact matches.
int internal_revoke(child_domain_t *child, capability_t *capa) {
  if (child == NULL || capa == NULL) {
    ERROR("null args.");
    goto failure;
  }

  if (capa->capa_type != Region) {
    ERROR("Error[internal revoke] supplied capability is not a revocation");
    goto failure;
  }

  if (tyche_revoke(capa->local_id) != SUCCESS) {
    goto failure;
  }

  if (enumerate_capa(capa->local_id, NULL, capa) != SUCCESS) {
    ERROR("Error[internal_revoke]: unable to enumerate the revoked capa");
    goto failure;
  }

  // Remove the capability and add it back to the local domain.
  dll_remove(&(child->revocations), capa, list);
  dll_add(&(local_domain.capabilities), capa, list);

  // Check if we can merge everything back.
  while (capa->parent != NULL &&
         ((capa->parent->right == capa && capa->parent->left != NULL &&
           capa->parent->left->capa_type == Region &&
           (capa->parent->left->info.region.flags & MEM_ACTIVE) == MEM_ACTIVE) ||
          (capa->parent->left == capa && capa->parent->right != NULL &&
           capa->parent->right->capa_type == Region && 
           (capa->parent->right->info.region.flags & MEM_ACTIVE) == MEM_ACTIVE))) {
    capability_t *parent = capa->parent;
    if (tyche_revoke(parent->local_id) != SUCCESS) {
      goto failure;
    }
    dll_remove(&(local_domain.capabilities), (parent->right), list);
    dll_remove(&(local_domain.capabilities), (parent->left), list);
    local_domain.dealloc(parent->left);
    local_domain.dealloc(parent->right);
    parent->left = NULL;
    parent->right = NULL;
    if (enumerate_capa(parent->local_id, NULL, parent) != SUCCESS) {
      ERROR("Error[internal_revoke]: unable to enumerate after the merge.");
      goto failure;
    }
    capa = parent;
  }

  // All done!
  DEBUG("success");
  return SUCCESS;
failure:
  ERROR("failure");
  return FAILURE;
}

int revoke_region(domain_id_t id, paddr_t start, paddr_t end) {
  child_domain_t *child = NULL;
  capability_t *capa = NULL;

  DEBUG("start");
  // Find the target domain.
  child = find_child(id); 

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("child not found.");
    goto failure;
  }

  // Try to find the region.
  dll_foreach(&(child->revocations), capa, list) {
    if (capa->capa_type == Region && capa->info.region.start == start &&
        capa->info.region.end == end) {
      // Found it!
      break;
    }
  }
  if (capa == NULL) {
    ERROR("Error[revoke_region]: unable to find region to revoke.");
    goto failure;
  }
  if (internal_revoke(child, capa) != SUCCESS) {
    goto failure;
  }
  DEBUG("success");
  return SUCCESS;
failure:
  ERROR("failure");
  return FAILURE;
}

// TODO nothing thread safe in this implementation for the moment.
int switch_domain(domain_id_t id, void *args) {
  child_domain_t *child = NULL;
  transition_t *wrapper = NULL;
  DEBUG("start");

  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("child not found.");
    goto failure;
  }

  // Acquire a transition handle.
  dll_foreach(&(child->transitions), wrapper, list) {
    if (wrapper->lock == TRANSITION_UNLOCKED) {
      wrapper->lock = TRANSITION_LOCKED;
      break;
    } else if (wrapper->lock != TRANSITION_LOCKED) {
      ERROR("There is an invalid lock value %d (%p) (child: %p)", wrapper->lock,
            (void *)wrapper, (void *)child);
      goto failure;
    }
  }
  if (wrapper == NULL) {
    ERROR("Unable to find a transition handle!");
    goto failure;
  }
  DEBUG("Found a handle for domain %lld, id %lld", id,
        wrapper->transition->local_id);

  if (tyche_switch(&(wrapper->transition->local_id), args) !=
      SUCCESS) {
    ERROR("failed to perform a switch on capa %lld",
          wrapper->transition->local_id);
    goto failure;
  }
  DEBUG("[switch_domain] Came back from the switch");
  // We are back from the switch, unlock the wrapper.
  wrapper->lock = TRANSITION_UNLOCKED;
  return SUCCESS;
failure:
  return FAILURE;
}

//TODO revoke domain is probably gonna be shit.
int revoke_domain(domain_id_t id) {
  child_domain_t *child = NULL;
  capability_t *capa = NULL;
  transition_t *wrapper = NULL;

  DEBUG("start");

  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    ERROR("unable to find the child.");
    goto failure;
  }

  // First go through all the revocations.
  while (!dll_is_empty(&(child->revocations))) {
    capa = child->revocations.head;
    if (capa->left != NULL) {
      // By construction this should never happen.
      ERROR("The revoked capa has non empty left.");
      goto failure;
    }
    if (capa->right != NULL) {
      // By construction this should never happen.
      ERROR("The revoked capa has non empty right.");
      goto failure;
    }
    if (internal_revoke(child, capa) != SUCCESS) {
      ERROR("unable to revoke a capability.");
      goto failure;
    }
  }
  // Take care of the transitions + manipulate.
  // No need to call revoke, they should be handled by the cascading revocation.
  while (!dll_is_empty(&(child->transitions))) {
    wrapper = child->transitions.head;
    capa = wrapper->transition;
    dll_remove(&(child->transitions), wrapper, list);
    local_domain.dealloc(capa);
    local_domain.dealloc(wrapper);
  }

  // Kill the domain.
  if (tyche_revoke(child->management->local_id) != SUCCESS) {
    goto failure;
  }
  local_domain.dealloc(child->management);

  // Dealloc the domain.
  dll_remove(&(local_domain.children), child, list);
  local_domain.dealloc(child);

  DEBUG("[revoke_domain] success");
  return SUCCESS;
failure:
  ERROR("[revoke_domain] failure");
  return FAILURE;
}
