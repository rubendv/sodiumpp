FROM ubuntu:16.04

RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install g++ clang cmake wget libsodium-dev
RUN mkdir /opt/sodiumpp
WORKDIR /opt/sodiumpp
