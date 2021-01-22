#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

char* to_lower(char *);
char* to_upper(char *);
bool string_starts_with(const char*, const char*);
bool string_ends_with(const char*, const char*);
bool is_numeric(const char *str);
char * get_user_input(char *);
bool get_user_long(char *, long int *);
bool get_user_double(char *, double *);
bool get_user_float(char *, float *);
void printf_center(char *, int, bool);