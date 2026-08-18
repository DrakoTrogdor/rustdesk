#ifndef SULLTEC_BRANDING_H_
#define SULLTEC_BRANDING_H_

// The fork's Windows-runner names, in one place because neither consumer can reach a Rust
// constant: Runner.rc is compiled by rc.exe and main.cpp runs before any Rust is loaded.
//
// The two forms are DIFFERENT and must stay different:
//
//   ST_PRODUCT_NAME  "SullTec Remote"  — what a human reads in the file properties dialog.
//   ST_APP_NAME_W    L"SullTecRemote"  — what the running window is TITLED, so it must equal
//                                        APP_NAME exactly. main.cpp hands it to FindWindowW to
//                                        focus an existing instance; a value that does not match
//                                        the real title finds no window and launches a second
//                                        copy instead of focusing the first. That is not
//                                        hypothetical: this carried the spaced form until 0.89.0
//                                        renamed APP_NAME, and nothing updated it.

#define ST_COMPANY_NAME "SullTec"
#define ST_PRODUCT_NAME "SullTec Remote"
#define ST_INTERNAL_NAME "sulltecremote"
#define ST_ORIGINAL_FILENAME "sulltecremote.exe"
#define ST_APP_NAME_W L"SullTecRemote"

#endif  // SULLTEC_BRANDING_H_
