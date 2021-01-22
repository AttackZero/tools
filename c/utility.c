#include "utility.h"
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>

/*
    Changes all uppercase characters in *str to lowercase.

    Returns: A pointer to str that has had all of its letters lowercased.
*/
char* to_lower(char *str)
{
    for (char *ptr=str; *ptr; ptr++)
    {
        *ptr = tolower(*ptr);
    }

    return str;
}

/*
    Changes all lowercase characters in *str to uppercase.

    Returns: A pointer to str that has had all of its letters uppercased.
*/
char* to_upper(char *str)
{
    for (char *ptr=str; *ptr; ptr++)
    {
        *ptr = toupper(*ptr);
    }

    return str;
}

/*
    Returns true if str starts with the characters in other, false otherwise
*/
bool string_starts_with(const char* str, const char* other)
{
    if (!str || !other)
    {
        return false;
    }
    return strncmp(other, str, strlen(other)) == 0;
}

/*
    Returns true if str ends with the characters in other, false otherwise
*/
bool string_ends_with(const char* str, const char* other)
{
    if (!str || !other)
    {
        return false;
    }
    size_t str_length = strlen(str);
    size_t other_length = strlen(other);

    if (other_length > str_length)
    {
        return false;
    }

    return strncmp(str + str_length - other_length, other, other_length) == 0;
}

/*
    Returns true if the string represents a number, false otherwise
*/
bool is_numeric(const char *str)
{
    if (!str)
    {
        return false;
    }

    char *leftover_chars;
    strtod(str, &leftover_chars);

    return (strlen(str) == (size_t)(leftover_chars - str));
}

/*
    Gets user input of an arbitrary size and returns a string containing that input
*/
char * get_user_input(char *prompt)
{
    unsigned int initial_input_size = 16;
    unsigned int current_input_size = initial_input_size;
    unsigned int current_input_position = 0;
    char *user_input = (char *) malloc(initial_input_size);
    int c = EOF;

    if (user_input != NULL)
    {
        printf("%s", prompt);
        while((c = getchar()) != '\n' && c != EOF)
        {
            user_input[current_input_position++] = (char) c;
            /*
                Need room for the null terminator, so resize if
                we are one smaller than the amount of memory we
                have allocated
            */
            if (current_input_position == current_input_size - 1)
            {
                /*
                    Reallocate the string by initial_input_size bytes + 1 (the + 1 is for
                    the null terminator)
                */
                current_input_size = current_input_position + initial_input_size + 1;
                user_input = realloc(user_input, current_input_size * sizeof(char));
                if (user_input == NULL)
                {
                    printf("Out of memory!\n");
                    free(user_input);
                    user_input = NULL;
                    return user_input;
                }
            }
        }
        // Null terminate the string
        user_input[current_input_position] = '\0';

        // If we have allocated more memory than necessary, resize the allocation
        if (current_input_position < current_input_size)
        {
            user_input = realloc(user_input, (current_input_position + 1) * sizeof(char));
            // There should not be any issues reallocating because we are allocating to a smaller size than currently allocated.
        }
    }

    return user_input;
}


bool get_user_long(char *prompt, long int *result)
{
    char *leftover_input = NULL;
    char *user_input = NULL;
    char *user_input_lower = NULL;
    int int_base = 10;
    size_t input_length;
    size_t bytes_consumed;

    user_input = get_user_input(prompt);
    if (strlen(user_input) == 0)
    {
        free(user_input);
        user_input = NULL;
        *result = 0;
        return false;
    }

    user_input_lower = to_lower(user_input);
    // Look for 0x
    if (string_starts_with(user_input_lower, "0x"))
    {
        int_base = 16;
    }
    // Look for 0 (octal)
    else if (string_starts_with(user_input_lower, "0"))
    {
        int_base = 8;
    }
    // If both of these fail, assume base 10
    else
    {
        int_base = 10;
    }
    *result = strtol(user_input, &leftover_input, int_base);

    /*
        Check to make sure the entire string was consumed.
        We can do that by checking if the distance in memory
        of leftover_input is equal to the length of user_input.

        strtod sets leftover_input to point to the byte in
        user_input after the conversion.  If that byte is
        strlen(user_input) away from the beginning of user_input,
        then we know the entire string was good.

        In theory, we should be able to check that the character
        pointed to by leftover_input is the null character (since
        if the whole string was consumed, the character after the last byte
        would be the null terminator), but this does not seem to work.
    */
    input_length = strlen(user_input);
    bytes_consumed = (size_t)(leftover_input - user_input);

    // No longer need user input, so free it.
    free(user_input);
    user_input = NULL;

    if (bytes_consumed != input_length)
    {
        return false;
    }
    else
    {
        return true;
    }
}

bool get_user_double(char *prompt, double *result)
{
    char *leftover_input = NULL;
    char *user_input = NULL;
    size_t input_length;
    size_t bytes_consumed;

    user_input = get_user_input(prompt);
    if (strlen(user_input) == 0)
    {
        free(user_input);
        user_input = NULL;
        *result = 0.0;
        return false;
    }
    *result = strtod(user_input, &leftover_input);

    /*
        Check to make sure the entire string was consumed.
        We can do that by checking if the distance in memory
        of leftover_input is equal to the length of user_input.

        strtod sets leftover_input to point to the byte in
        user_input after the conversion.  If that byte is
        strlen(user_input) away from the beginning of user_input,
        then we know the entire string was good.

        In theory, we should be able to check that the character
        pointed to by leftover_input is the null character (since
        if the whole string was consumed, the character after the last byte
        would be the null terminator), but this does not seem to work.
    */
    input_length = strlen(user_input);
    bytes_consumed = (size_t)(leftover_input - user_input);
    
    // No longer need user input, so free it.
    free(user_input);
    user_input = NULL;

    if (bytes_consumed != input_length)
    {
        return false;
    }
    else
    {
        return true;
    }
}

bool get_user_float(char *prompt, float *result)
{
    char *leftover_input;
    size_t input_length;
    size_t bytes_consumed;
    char *user_input = get_user_input(prompt);
    if (strlen(user_input) == 0)
    {
        free(user_input);
        user_input = NULL;
        *result = 0.0;
        return false;
    }

    *result = strtof(user_input, &leftover_input);

    /*
        Check to make sure the entire string was consumed.
        We can do that by checking if the distance in memory
        of leftover_input is equal to the length of user_input.

        strtof sets leftover_input to point to the byte in
        user_input after the conversion.  If that byte is
        strlen(user_input) away from the beginning of user_input,
        then we know the entire string was good.

        In theory, we should be able to check that the character
        pointed to by leftover_input is the null character (since
        if the whole string was consumed, the character after the last byte
        would be the null terminator), but this does not seem to work.
    */
    input_length = strlen(user_input);
    bytes_consumed = (size_t)(leftover_input - user_input);
    
    // No longer need user input, so free it.
    free(user_input);
    user_input = NULL;
    
    if (bytes_consumed != input_length)
    {
        return false;
    }
    else
    {
        return true;
    }
}

void printf_center(char *str, int field_length, bool print_endline)
{
    int padding_length = (field_length - strlen(str)) / 2;

    /*
        The padding length on the right side will be adjusted if it is even because we
        lose precision when it is odd (the not integral part is chopped off, which means
        we are off by 0.5 characters on either side).

        Example:
        Field length 40, string length 10: (40 - 10) / 2 = 15 padding length
        15 + 15 + 10 = 40, so this is okay.

        Field length 40, string length 11: (40 - 11) / 2 = 14 padding length
        14 + 14 + 11 = 39 - This is not okay.  It is off by 1.
    */
    printf("%*s%s%*s", padding_length, " ", str, (field_length - strlen(str)) % 2 == 0 ? padding_length - 1 : padding_length, " ");

    if (print_endline)
    {
        printf("\n");
    }

    return;
}