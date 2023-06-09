# 004 - PMP Overflow

## What?

On Risc-V, we only have a limited number of PMPs, but there is no limit on the number of memory regions a domain can have, hence some configuration can not be expressed by the hardware.

To handle the situation there are two solutions:
- Prevent operation that would cause PMP overflow.
- Handle PMP overflows.

I believe the second solution is much easier and elegant to implement.

## Why?

Preventing operation that would cause PMP overflow is complex, because both adding and removing a region to a domain can cause a PIMP overflow.
Operation such as revoke cause cascading deletion of domains and resources, and therefore have a huge blast radius in terms of impact on other domains.
Preventing revoke operation from succeeding is problematic, as untrusted code could configure its own domain so that it can's be revoked without causing and overflow, effectively causing a DoS.
Adding to that, we must consider the complexity of detecting overflows, which is itself non trivial and might require simulation/rollback of complex operations.

On the other hand, handling the PMP overflow lazily by rising a trap, as described in design document `0003`, can be trivially implemented without modification of the capability engine.

## How?

When switching to a domain, if the PMP entries can not be constructed due to a PMP overflow, then a PMP trap should be raised.
The domain's manager should take actions accordingly, either removing regions from the domain or destroying it.
