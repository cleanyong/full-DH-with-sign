please watch this video on YouTube

https://youtu.be/gKm0tDoyAJc?si=onybj6DbPapgZRDC


# build and install
- install Rust first
- git clone this repo
- cargo build --release
- cargo install --path .
- cd to any empty folder you like

# 操作步骤for alice

cargo run -- alice

或者

./target/debug/full-DH-with-sign alice

or

full-DH-with-sign alice


# 操作步骤for bob

cargo run -- bob

或者

./target/debug/full-DH-with-sign bob
