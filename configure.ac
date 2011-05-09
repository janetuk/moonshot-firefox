AC_PREREQ(2.66)
AC_INIT([firefox-moonshot],[0.0.1],
[bugs@project-moonshot.org], [Moonshot Firefox extension])
AM_INIT_AUTOMAKE([1.11 foreign])
AC_PROG_CXX
AC_PROG_RANLIB

PKG_CHECK_MODULES(XUL, libxul)
MOZ_SDKDIR=`pkg-config libxul --variable sdkdir`
MOZ_IDLDIR=`pkg-config libxul --variable idldir`
# We need to override cflags for unstable APIs
XUL_CFLAGS=`pkg-config --cflags libxul --define-variable=includetype=unstable`
AC_SUBST([MOZ_IDLDIR])
AC_SUBST([MOZ_SDKDIR])
AC_PATH_PROG([XPIDL], [xpidl], false, [$MOZ_SDKDIR/bin$PATH_SEPARATOR$PATH])
if [ $XPIDL = "false" ] ;then
   AC_ERROR([Couldn't find xpidl])
fi

AC_CHECK_LIB([gssapi_krb5], [gss_init_sec_context])

AC_CHECK_HEADERS(gssapi.h gssapi_ext.h)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
