FROM rust:latest


RUN echo "[source.crates-io]" > /usr/local/cargo/config \
    && echo 'registry = "https://github.com/rust-lang/crates.io-index"' >> /usr/local/cargo/config \
    && echo 'replace-with = "ustc"' >> /usr/local/cargo/config \
    && echo '[source.ustc]' >> /usr/local/cargo/config \
    && echo 'registry = "git://mirrors.ustc.edu.cn/crates.io-index"' >> /usr/local/cargo/config

RUN mkdir -p /code/src
ADD src /code/src
ADD Cargo.toml /code/
ADD rustfmt.toml /code/
ADD Dockerfile /code/
ADD README.md /code/
ADD LICENSE /code/

RUN cd /code && cargo build


RUN echo "deb http://mirrors.163.com/debian/ stretch main" > /etc/apt/sources.list \
    && echo "deb http://mirrors.163.com/debian/ stretch-updates main non-free contrib" >> /etc/apt/sources.list \
    && echo "deb-src http://mirrors.163.com/debian/ stretch-updates main non-free contrib" >> /etc/apt/sources.list \
    && echo "deb http://mirrors.163.com/debian-security/ stretch/updates main non-free contrib" >> /etc/apt/sources.list \
    && echo "deb http://httpredir.debian.org/debian stretch-backports main contrib non-free" >> /etc/apt/sources.list

RUN apt -y update
RUN apt -y install locales bash-completion vim fish tmux htop 

RUN echo "zh_CN.UTF-8 UTF-8" > /etc/locale.gen \
    && echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen \
    && locale-gen
RUN echo "syntax on" >> /etc/vim/vimrc \
    && echo "set nu" >> /etc/vim/vimrc
RUN mkdir -p /root/.config/fish \
    && echo "set -gx PATH /usr/local/cargo/bin \$PATH" > ~/.config/fish/config.fish

