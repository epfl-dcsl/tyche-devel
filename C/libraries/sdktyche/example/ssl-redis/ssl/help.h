#pragma once

// —————————————————————————— Debugging functions ——————————————————————————— //
/// Crashes the domain by performing a pointer dereference to 0xdeadbabe.
/// The compiler usually puts the value (666) to be written into rax.
void suicide(void);

/// Performs a vmcall #10 to tyche with marker as the first argument.
void tyche_debug(unsigned long long marker);
