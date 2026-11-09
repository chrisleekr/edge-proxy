# Autopilot runner image: the runner's TypeScript runs on Node's type
# stripping, on distroless as nonroot. Only production dependencies, and
# test/ (the scripted adapter) is never copied in.
#
# npm runs on the build host and installs the optional packages for the
# target's OS, CPU and libc, so a multi-platform build needs no emulation
# and each platform holds only its own glibc Claude Code binary.
FROM --platform=$BUILDPLATFORM node:26.13.0-trixie-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS deps
ARG TARGETARCH
WORKDIR /app
COPY autopilot/package.json autopilot/package-lock.json ./
RUN cpu="${TARGETARCH}"; [ "${cpu}" = amd64 ] && cpu=x64; \
    npm ci --omit=dev --ignore-scripts --os=linux --libc=glibc --cpu="${cpu}"

FROM gcr.io/distroless/nodejs26-debian13:nonroot@sha256:33c86a63859efc2ebd88ea0a355863582ec6f1220d048de62baffb2584e709b3
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY autopilot/package.json ./
COPY autopilot/src ./src
CMD ["src/main.ts"]
