FROM scratch

COPY dist/auto-server /auto-server

EXPOSE 1080

USER 65532:65532

ENTRYPOINT ["/auto-server"]
