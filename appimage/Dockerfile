# Use Ubuntu for AppImage compatibility
FROM ubuntu:24.04

# Install build dependencies
RUN apt-get update && apt-get install -y \
    meson \
    ninja-build \
    python3 \
    python3-gi \
    gir1.2-gtk-3.0 \
    gettext \
    desktop-file-utils \
    libglib2.0-bin \
    wget \
    file \
    fuse \
    pkg-config \
    libpam0g-dev \
    && rm -rf /var/lib/apt/lists/*

# AppImage tools work better as non-root
USER 1000
WORKDIR /home/ubuntu

# Download appimagetool
RUN wget -O appimagetool https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage && \
    chmod +x appimagetool

# Set up the build script
COPY --chown=1000:1000 build-appimage-docker.sh /home/ubuntu/
RUN chmod +x build-appimage-docker.sh

# Entry point
ENTRYPOINT ["./build-appimage-docker.sh"]
