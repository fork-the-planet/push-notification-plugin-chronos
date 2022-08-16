m4_define([chronos_push_notification_plugin_VERSION],
  m4_esyscmd_s([build-aux/git-version-gen]))

m4_define([chronos_push_notification_plugin_ABI_VERSION],
  m4_esyscmd_s([build-aux/git-abi-version-gen]))))

m4_define([chronos_push_notification_plugin_TAR_VERSION],
  m4_esyscmd_s([build-aux/git-tarname-version-gen]))))

AC_PREREQ([2.69])

AC_INIT([Chronos Push Notification Plugin],
        [m4_defn([chronos_push_notification_plugin_VERSION])],
        [dovecot@dovecot.org],
        [m4_defn([chronos_push_notification_plugin_TAR_VERSION])])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_HEADERS([dummy-config.h])

AM_INIT_AUTOMAKE([no-define foreign tar-ustar])
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE

PKG_PROG_PKG_CONFIG

AC_PROG_CC
AC_PROG_CPP
LT_INIT

DC_DOVECOT
DC_DOVECOT_MODULEDIR
LIBDOVECOT_INCLUDE="$LIBDOVECOT_INCLUDE $LIBDOVECOT_STORAGE_INCLUDE"
CFLAGS="$CFLAGS $EXTRA_CFLAGS"
LIBS="$DOVECOT_LIBS"
BINARY_CFLAGS="$PIE_CFLAGS"
BINARY_LDFLAGS="$PIE_LDFLAGS $RELRO_LDFLAGS"
AC_SUBST(BINARY_CFLAGS)
AC_SUBST(BINARY_LDFLAGS)
AC_SUBST(LIBDOVECOT_INCLUDE)
AC_SUBST(LIBDOVECOT_PUSH_NOTIFICATION_INCLUDE)

AS_IF([test "$AR_FLAGS" = "cru"], [AR_FLAGS="cr"], [])
AC_SUBST([AR_FLAGS])

AC_CONFIG_FILES([
Makefile
src/Makefile
build-aux/run-test.sh
stamp.h])

AC_OUTPUT
