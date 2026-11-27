# Autopilot runner image: the runner's TypeScript runs on Node's type
# stripping, on distroless as nonroot. Only production dependencies, and
# test/ (the scripted adapter) is never copied in.
#
# npm runs on the build host and installs the optional packages for the
# target's OS, CPU and libc, so a multi-platform build needs no emulation
# and each platform holds only its own glibc Claude Code binary.
FROM --platform=$BUILDPLATFORM node:26.13.1-trixie-slim@sha256:abe7e5a82b61a8ef67b315b85497c9e65173387ccf2f4a029248184b8e020be5 AS deps
ARG TARGETARCH
WORKDIR /app
COPY autopilot/package.json autopilot/package-lock.json ./
RUN cpu="${TARGETARCH}"; [ "${cpu}" = amd64 ] && cpu=x64; \
    npm ci --omit=dev --ignore-scripts --os=linux --libc=glibc --cpu="${cpu}"

FROM gcr.io/distroless/nodejs26-debian13:nonroot@sha256:a84242e747fbb5aaaa0180c273b6f7130ca34b3300082192ef58eea96089eb3c
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY autopilot/package.json ./
COPY autopilot/src ./src
CMD ["src/main.ts"]
