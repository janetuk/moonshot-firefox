Building for windows:
install MSVC 2010 Express
install mit kerberos for windows
install xulrunner 1.9.2 SDK
install firefox 3.6.18
build moonshot mech_eap.dll
set environment variables:
XRSDK=<Path to xulrunner 1.9.2 SDK>
KRB_INSTALL_DIR=<Path to krb install dir>
create $(KRB_INSTALL_DIR)/@sysconfdir/gss/mech with contents:
eap-aes128		1.3.6.1.4.1.5322.22.1.17	<Path to mech_eap.dll>
eap-aes256		1.3.6.1.4.1.5322.22.1.18	<Path to mech_eap.dll>

open MoonshotFirefox.sln
build.  *dbg/opt configuration must match mech_eap.dll, krb5_32.dll, gssapi.dll*

Testing:
run firefox.exe
File -> Open file -> MoonshotFirefox.xpi (from Debug/Release subdirectory as appropriate)
close firefox
run firefox.exe from $(KRB_INSTALL_DIR)/bin
