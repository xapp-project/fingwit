# Use Ubuntu for AppImage compatibility
FROM ubuntu:22.04

# Install build dependencies
RUN apt-get update && apt-get install -y \
    meson \
    ninja-build \
    python3 \
    python3-gi \
    gir1.2-gtk-3.0 \
    gettext \
    desktop-file-utils \
    wget \
    file \
    fuse \
    && rm -rf /var/lib/apt/lists/*

# Create build user (AppImage tools work better as non-root)
RUN useradd -m -u 1000 builder
USER builder
WORKDIR /home/builder

# Download appimagetool
RUN wget -O appimagetool https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage && \
    chmod +x appimagetool

# Set up the build script
COPY --chown=builder:builder build-appimage-docker.sh /home/builder/
RUN chmod +x build-appimage-docker.sh

# Entry point
ENTRYPOINT ["./build-appimage-docker.sh"]
