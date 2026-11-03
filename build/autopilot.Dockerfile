# Autopilot runner image: the runner's TypeScript runs on Node's type
# stripping, on distroless as nonroot. Only production dependencies, and
# test/ (the scripted adapter) is never copied in.
#
# npm runs on the build host and installs the optional packages for the
# target's OS, CPU and libc, so a multi-platform build needs no emulation
# and each platform holds only its own glibc Claude Code binary.
FROM --platform=$BUILDPLATFORM node:26.13.0-trixie-slim@sha256:e4db4c914bf8ad241bd24804fc25d272d89bad97e68cdc8a1414862790a02c39 AS deps
ARG TARGETARCH
WORKDIR /app
COPY autopilot/package.json autopilot/package-lock.json ./
RUN cpu="${TARGETARCH}"; [ "${cpu}" = amd64 ] && cpu=x64; \
    npm ci --omit=dev --ignore-scripts --os=linux --libc=glibc --cpu="${cpu}"

FROM gcr.io/distroless/nodejs26-debian13:nonroot@sha256:9b945e92c1b5463a4b75f11e8417515e4bea7355f6adfd79ec220fbbe905dda8
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY autopilot/package.json ./
COPY autopilot/src ./src
CMD ["src/main.ts"]
