extern crate chrono;
extern crate chrono_tz;

use chrono::offset::TimeZone;

use chrono_tz::US::Pacific;
use chrono_tz::Asia::Shanghai;

pub use chrono_tz::*;

fn main(){
    let pacific_time = Pacific.ymd(1990, 5, 6).and_hms(12, 30, 45);
    let shanghai_time = Shanghai.ymd(2017, 10, 6).and_hms(22, 03, 00);
    println!("pacific_time : {:?}", pacific_time.to_rfc3339());   // 1990-05-06T12:30:45-07:00
    println!("shanghai_time: {:?}", shanghai_time.to_rfc3339());  // 2017-10-06T22:03:00+08:00
}