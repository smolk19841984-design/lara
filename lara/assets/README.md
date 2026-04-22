# Bundled assets (build-time placeholders)

This directory is copied into the app bundle by `scripts/build_ipa_wsl.sh`.

The build expects these paths to exist:

- `assets/bootstrap-ssh-iphoneos-arm64.tar.zst`
- `assets/tools/tar`
- `assets/tools/libiosexec.1.dylib`
- `assets/tools/libintl.8.dylib`

In this repository snapshot the real payload binaries are not included.
The committed files are **placeholders** so the IPA build can complete.

Replace them with real artifacts in your environment if you need runtime functionality.

