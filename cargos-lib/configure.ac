#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(cargos-lib, 0.1.4, porto_@users.sourceforge.net)
AC_CONFIG_SRCDIR(config.h.in)

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])

AC_ARG_ENABLE([debug], [AC_HELP_STRING([--enable-debug],
		[extensive debugging messages [default=no]])],
		[debugmode="$enableval"], [debugmode="no"])

if test "x$debugmode" = "xyes"; then
	AC_DEFINE(CARGOS_DEBUG, [1], [Define to 1 if you want to enable extensive debugging messages])
	CPPFLAGS="$CPPFLAGS -Wall"
fi



# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AM_MISSING_PROG(PERL, perl, $missing_dir)

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h stdlib.h string.h getopt.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_BIGENDIAN
AC_C_INLINE
AC_TYPE_SIZE_T

dnl **************************************************
dnl * large filesystem Support                       *
dnl **************************************************

AC_MSG_CHECKING(for Large File System support)
AC_ARG_ENABLE(lfs,
 AC_HELP_STRING([--enable-lfs],[Turn on Large File System (default)]),
 [case "$host" in
 *-*-linux*)
 case "${enableval}" in
    yes) CPPFLAGS="${CPPFLAGS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES" ;;
     no) ;;
      *) AC_MSG_ERROR(bad value ${enableval} for --enable-lfs) ;;
   esac
   ;;
 esac],[
 CPPFLAGS="${CPPFLAGS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES"
 enable_lfs=yes]
 ,enable_lfs=no,)
AC_MSG_RESULT($enableval)

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strdup getopt_long])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
