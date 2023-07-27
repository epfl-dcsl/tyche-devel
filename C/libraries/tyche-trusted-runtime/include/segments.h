#pragma once

// ——————————————————————————————— Functions ———————————————————————————————— //
int save_segments(uint16_t* ds, uint16_t* es, uint16_t* ss);
int restore_segments(uint16_t* ds, uint16_t* es, uint16_t* ss);
