FROM scratch
COPY hello /hello
USER 1000:1000
ENTRYPOINT ["/hello"]
