#pragma once

#include "ubench.h"

#define COL_WIDTH (25)
#define MAX_NB_COLS (4)
#define DISP_INPUT (COL_WIDTH * 2)

void print_line(char** cols, size_t len);

void display_config(ubench_config_t* bench);

char** allocate_buffer(void);

void free_buffer(char** buf);
