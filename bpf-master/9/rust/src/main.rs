#![feature(asm)]
use probe::probe;
use std::{thread, time};

#[no_mangle]
fn my_world(value: u64) -> u64 {
        println!("world!");
        return value;
}
 
#[no_mangle]
fn my_hello(value: u64) -> u64 {
        probe!(myprobe, begin);
        print!("Hello, ");
        my_world(1000);
        probe!(myprobe, end);
        return value;
}

fn main() {
    let duration = time::Duration::from_millis(10000);
    my_hello(100);
    thread::sleep(duration);
}
