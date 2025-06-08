# Fingwit

![shadow_fingwit](https://github.com/user-attachments/assets/7af684eb-8c78-4b3b-9e75-40e5730713c6)

Fingwit is used to configure fingerprint authentication.

It's an XApp so it can work in any distribution and many desktop environments.

# AppImage

An AppImage for fingwit is available in the releases section.

# PAM Configuration

Fingwit uses two PAM modules:

- Its own module: `pam_fingwit.so`
- Fprint's module: `pam_fprintd.so`

`pam_fprintd.so` performs the fingerprint authentication.

`pam_fingwit.so` decides when it's safe for the computer to use `pam_fprintd.so` and when it's better to skip it (for instance when you try to log in with an encrypted home directory).

A typical PAM configuration therefore looks like this:

```
auth	[authinfo_unavail=1 default=ignore]	pam_fingwit.so # debug
auth	[success=end default=ignore]	pam_fprintd.so max-tries=1 timeout=10 # debug
auth	[success=1 default=ignore]	pam_unix.so nullok
```

If `pam_fingwit.so` thinks fingerprint authentication is safe, it returns `ignore` and lets PAM proceed towards `pam_fprintd.so`.

If `pam_fingwit.so` thinks fingerprint authentication should be avoided, it returns `authinfo_unavail` and tells PAM to skip `pam_fprintd.so`.

# Dependencies

## Runtime Dependencies
- python3
- python3-gi
- python3-pam
- gir1.2-gtk-3.0
- fprintd
- libpam-fprintd

## Build Dependencies
- meson (>= 0.59.0)
- ninja-build
- python3
- gettext
- debhelper-compat (= 13) if you want to build a Debian package

# Building from source

## For Debian distributions (Mint, Ubuntu, etc..)

```bash
sudo apt install debhelper-compat meson ninja-build python3 gettext
dpkg-buildpackage
```

This will create a `.deb` package in the parent directory.

After you install the `.deb` package, you can run `fingwit` from the command line, or find it in the `Preferences` category of your application menu.

## For other distributions

Fingwit uses the Meson build system:

```bash
# Install build dependencies (example for different distros)
# Fedora: sudo dnf install meson ninja-build python3 gettext
# Arch: sudo pacman -S meson ninja python gettext
# openSUSE: sudo zypper install meson ninja python3 gettext-tools

# Build and install
meson setup builddir --prefix=/usr/local
meson compile -C builddir
sudo meson install -C builddir
```

## Development Build

For development and testing without installing:

```bash
meson setup builddir
meson compile -C builddir
# Run directly from build directory
./builddir/fingwit
```

## Creating an AppImage

An AppImage is a portable application format that runs on any Linux distribution without installation.

### Prerequisites

- Docker installed on your system
- x86_64 architecture

### Building the AppImage

```bash
cd appimage/
./build.sh
```

This will:
1. Build a Docker container with all dependencies
2. Build fingwit using Meson inside the container  
3. Create a portable AppImage file
4. Output: `appimage/fingwit.AppImage`

### Running the AppImage

```bash
# Make executable and run
chmod +x fingwit.AppImage
./fingwit.AppImage

# Or extract and run (if FUSE is not available)
./fingwit.AppImage --appimage-extract-and-run
```

**Note:** The AppImage requires the host system to have fprintd service running and fingerprint hardware drivers installed, as it provides the application but relies on the host for system integration.

# Translations

Please use Launchpad to translate Fingwit: https://translations.launchpad.net/linuxmint/latest/.

The PO files in this project are imported from there.

# License

- Code: GPLv3
