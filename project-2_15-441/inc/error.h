#ifndef ERROR_H
#define ERROR_H


#define CHK(__va_args__)\
{\
  if(!(__va_args__)) {\
    return EXIT_FAILURE; }\
}

#define CHK_MSG(MSG, __va_args__)\
{\
  if(!(__va_args__)) {\
    perror(MSG);\
    return EXIT_FAILURE; \
  }\
}


#endif
