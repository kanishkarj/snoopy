FROM rust:latest

RUN apt-get update \
    && apt-get install -y libpcap-dev
    
RUN mkdir /snoopy
WORKDIR /snoopy
COPY . /snoopy/

RUN cargo build --release;

ENTRYPOINT ["./target/release/snoopy", "capture", "run"]