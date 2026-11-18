# Autopilot runner image: the runner's TypeScript runs on Node's type
# stripping, on distroless as nonroot. Only production dependencies, and
# test/ (the scripted adapter) is never copied in.
#
# npm runs on the build host and installs the optional packages for the
# target's OS, CPU and libc, so a multi-platform build needs no emulation
# and each platform holds only its own glibc Claude Code binary.
FROM --platform=$BUILDPLATFORM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS deps
ARG TARGETARCH
WORKDIR /app
COPY autopilot/package.json autopilot/package-lock.json ./
RUN cpu="${TARGETARCH}"; [ "${cpu}" = amd64 ] && cpu=x64; \
    npm ci --omit=dev --ignore-scripts --os=linux --libc=glibc --cpu="${cpu}"

FROM gcr.io/distroless/nodejs26-debian13:nonroot@sha256:1d736cf8b5716c07a245301f92717143215d248fd55771ee1936ef4b3302e531
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY autopilot/package.json ./
COPY autopilot/src ./src
CMD ["src/main.ts"]
