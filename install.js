// Moonshot

var gVersion = "0.1";

var err = initInstall("Moonshot Authentication Module", "MoonshotModule", gVersion);
logComment("initInstall: " + err);

var fDir = getComponentsFolder();
logComment("fComponents: " + fDir);

err = addFile("", gVersion, "components/moonshot.xpt", fDir, "", true);
logComment("addFile: " + err);
err = addFile("", gVersion, "components/libmoonshot.so", fDir, "", true);
logComment("addFile: " + err);

if (getLastError() == SUCCESS) {
  err = performInstall(); 
  logComment("performInstall: " + err);
} else {
  cancelInstall(err);
}


