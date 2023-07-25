# 007 - Region Access Rights

## What

Region access rights must be enforced by the monitor and thus be present in region capabilities.
Each region capability encodes start, end, and ops access rights.
Ops encode read (R), write (W), execute (X), and super (S) memory access rights.
The super access right pertains to the ability to execute supervisor mode code.
We need to determine a default behavior for this.

## Why

Domains so far are associated with page tables that already provide a first layer of access management.
However, some domains can execute in privilege mode and change their own mappings.
There is therefore a need for the monitor to enforce access rights.

## How

These access rights have been added to the Region capa.
In the capa-engine region tracker, there is a counter for each individual access right per region.
This allows to have, e.g., multiple read capabilities on a given region and determine, upon losing one, whether the region should be made unavailable or not.
Updates to the region in the monitor (e.g., re-generating the EPTs) are triggered when an access right is either lost of acquire.
