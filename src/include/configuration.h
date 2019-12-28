#ifndef __CONFIGURATION_H_INCLUDED__
#define __CONFIGURATION_H_INCLUDED__

#if !defined(__GNUC__) && (__GNUC__ < 5) && (__STDC_VERSION__ < 201112)
  #error "Need GCC 5 or greater, with C11 standard support, to compile!"
#endif

/* Name of package */
#define PACKAGE "t50"

/* Define to the version of this package. */
#define PACKAGE_VERSION "5.8.7"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "t50-dev@googlegroups.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME PACKAGE " " PACKAGE_VERSION

/* Define to the home page for this package. */
#define PACKAGE_URL "https://gitlab.com/fredericopissarra/t50.git"

/* Use fork to spawn extra process */
#define __HAVE_TURBO__

#endif
