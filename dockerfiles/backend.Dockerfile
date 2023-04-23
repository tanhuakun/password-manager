## Dockerfile for building webserver!

## Step 1: Build rust

FROM rust:1.68 as rust-server
WORKDIR /rust-server
COPY ./rust-server .
## existing builds cause issues, probably due to cache
RUN rm -rf /rust-server/target
RUN cargo build -r

## Step 2: Get debian image, install dependencies
## alpine is not used due to performance considerations of musl libc as well as dependency issues 
FROM debian:buster-slim
WORKDIR /app
RUN apt update
# for mysqlclient for diesel
RUN apt install -y libmariadb3
# for openssl stuff for reqwest
RUN apt install -y libssl1.1
# updated ca certificates
RUN apt install -y ca-certificates
RUN apt clean

## Step 3: Copy and run binary
COPY --from=rust-server /rust-server/target/release/rust-server /app/rust-server

ENTRYPOINT ["/app/rust-server"]