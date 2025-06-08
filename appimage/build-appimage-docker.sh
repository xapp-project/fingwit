#!/bin/bash
# Docker-based AppImage build script for fingwit

set -e

echo "Building fingwit AppImage in Docker..."

# Source should be mounted at /src
cd /src

# Clean any existing build artifacts and create fresh AppDir
rm -rf appimage/AppDir appimage/builddir
mkdir -p appimage/AppDir/usr

# Build and install fingwit to AppDir (use separate builddir for docker)
echo "Building with Meson..."
meson setup appimage/builddir --prefix=/usr
meson compile -C appimage/builddir
DESTDIR=$PWD/appimage/AppDir meson install -C appimage/builddir

# Compile GSettings schemas for AppImage
echo "Compiling GSettings schemas for AppImage..."
if [ -d "appimage/AppDir/usr/share/glib-2.0/schemas" ]; then
    glib-compile-schemas appimage/AppDir/usr/share/glib-2.0/schemas/
    echo "Schemas compiled successfully"
    ls -la appimage/AppDir/usr/share/glib-2.0/schemas/
else
    echo "Warning: No schemas directory found"
fi

echo "Creating AppRun script..."
# Create AppRun script
cat > appimage/AppDir/AppRun << 'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "${0}")")"
export PATH="${HERE}/usr/bin:${PATH}"
export PYTHONPATH="${HERE}/usr/lib/fingwit:${PYTHONPATH}"
export XDG_DATA_DIRS="${HERE}/usr/share:${XDG_DATA_DIRS}"
export GI_TYPELIB_PATH="${HERE}/usr/lib/girepository-1.0:${GI_TYPELIB_PATH}"
exec "${HERE}/usr/bin/fingwit" "$@"
EOF
chmod +x appimage/AppDir/AppRun

echo "Setting up desktop file and icon..."
# Copy desktop file and icon to AppDir root
cp appimage/AppDir/usr/share/applications/fingwit.desktop appimage/AppDir/
# Use the correct icon from your data/icons structure
cp appimage/AppDir/usr/share/icons/hicolor/scalable/apps/fingwit.svg appimage/AppDir/fingwit.svg

echo "Creating AppImage..."
# Create AppImage using the pre-downloaded appimagetool with explicit architecture
cd appimage
ARCH=x86_64 /home/builder/appimagetool --appimage-extract-and-run AppDir fingwit.AppImage

echo "AppImage created successfully: appimage/fingwit.AppImage"
echo "Note: fingwit requires hardware access for fingerprint readers."
echo "You may need to run with --appimage-extract-and-run on some systems."

# Make sure the output is owned by the host user
chown 1000:1000 fingwit.AppImage 2>/dev/null || true