#include "utility.h"

char * get_user_input(char * prompt)
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
    }
    
    // Null terminate the string
    user_input[current_input_position] = '\0';

    return user_input;
}