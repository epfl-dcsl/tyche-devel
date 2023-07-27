#pragma once

/// Return to user space.
/// TODO: probably need more state than that but for now it will do.
void blue_pill(unsigned long user_rip, unsigned long user_rsp);
