# Release image, built by GoReleaser (dockers_v2) from the prebuilt binary.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/kupre /usr/bin/kupre
USER 65532:65532
ENTRYPOINT ["/usr/bin/kupre"]
