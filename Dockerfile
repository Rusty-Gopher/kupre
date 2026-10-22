# Release image, built by GoReleaser (dockers_v2) from the prebuilt binary.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/kupre /usr/bin/kupre
USER 65532:65532
ENTRYPOINT ["/usr/bin/kupre"]
