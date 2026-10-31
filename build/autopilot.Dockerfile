# Autopilot runner image: the runner's TypeScript runs on Node's type
# stripping, on distroless as nonroot. Only production dependencies, and
# test/ (the scripted adapter) is never copied in.
#
# npm runs on the build host and installs the optional packages for the
# target's OS, CPU and libc, so a multi-platform build needs no emulation
# and each platform holds only its own glibc Claude Code binary.
FROM --platform=$BUILDPLATFORM node:26.12.1-trixie-slim@sha256:36793bcbb160a6a16cede1e62b93f84e26b78a972a8a4c0b879c1c12f22761ec AS deps
ARG TARGETARCH
WORKDIR /app
COPY autopilot/package.json autopilot/package-lock.json ./
RUN cpu="${TARGETARCH}"; [ "${cpu}" = amd64 ] && cpu=x64; \
    npm ci --omit=dev --ignore-scripts --os=linux --libc=glibc --cpu="${cpu}"

FROM gcr.io/distroless/nodejs26-debian13:nonroot@sha256:96455baef11b178fc135b32206e3922c515dbed2400676c94f907f8f84e6abf6
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY autopilot/package.json ./
COPY autopilot/src ./src
CMD ["src/main.ts"]
