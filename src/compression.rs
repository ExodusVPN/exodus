
use snap;

use std::str;


pub fn compress(input: &[u8], output: &mut [u8]) -> Result<usize, snap::Error> {
    let mut endcoder = snap::Encoder::new();
    endcoder.compress(input, output)
}

pub fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize, snap::Error> {
    let mut decoder = snap::Decoder::new();
    decoder.decompress(input, output)
}



fn test_snap_comress(){
    let data = r"PriKey:
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";
    let input = data.as_bytes();
    let max_output_len = snap::max_compress_len(input.len());
    println!("Input Len: {:?}", input.len());
    println!("Output Max Len: {:?}", max_output_len);

    let mut output: Vec<u8> = vec![0u8; max_output_len];
    let size = compress(data.as_bytes(), &mut output).unwrap();
    println!("{:?}", &output[..size]);
    println!("Output Len: {:?}", size);
}

fn test_snap_decompress(){
    let input = [240u8, 19, 32, 80, 114, 105, 75, 101, 121, 58, 10, 45, 1, 1, 80, 66,
    69, 71, 73, 78, 32, 82, 83, 65, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89,
    1, 25, 244, 59, 3, 45, 10, 77, 73, 73, 67, 88, 65, 73, 66, 65, 65, 75, 66, 103,
    81, 67, 43, 107, 55, 116, 67, 111, 84, 86, 56, 117, 97, 111, 72, 74, 104, 111,
    86, 88, 101, 51, 65, 119, 97, 100, 78, 108, 85, 117, 115, 86, 82, 47, 97, 80, 89,
    57, 101, 121, 122, 76, 113, 79, 78, 75, 122, 76, 108, 111, 105, 10, 89, 84, 51, 68,
    73, 106, 115, 103, 68, 69, 79, 81, 89, 106, 43, 52, 103, 73, 89, 52, 82, 120, 51, 74,
    71, 50, 69, 66, 83, 114, 97, 87, 113, 113, 101, 120, 112, 116, 87, 72, 121, 80, 116,
    88, 47, 118, 111, 56, 104, 99, 86, 57, 67, 114, 111, 84, 73, 82, 73, 101, 120, 85, 72,
    119, 10, 86, 55, 105, 83, 55, 74, 86, 65, 102, 48, 71, 76, 121, 70, 114, 51, 117, 86,
    82, 104, 48, 55, 83, 101, 113, 111, 78, 78, 107, 67, 104, 53, 65, 105, 105, 103, 117,
    112, 68, 48, 99, 113, 75, 97, 98, 65, 98, 79, 120, 70, 75, 85, 118, 104, 78, 56, 48,
    119, 73, 68, 65, 81, 65, 66, 10, 65, 111, 71, 66, 65, 76, 112, 78, 97, 122, 117, 111,
    111, 115, 81, 113, 77, 72, 104, 75, 110, 67, 99, 86, 75, 113, 53, 76, 52, 99, 83, 114,
    86, 85, 51, 68, 55, 90, 54, 73, 110, 90, 90, 54, 113, 71, 120, 109, 88, 106, 118, 66, 55,
    87, 85, 56, 107, 73, 99, 111, 43, 73, 110, 77, 10, 48, 50, 80, 98, 87, 66, 87, 67, 116,
    122, 78, 101, 43, 108, 81, 50, 67, 113, 43, 98, 110, 85, 70, 79, 49, 82, 122, 88, 55, 73,
    88, 111, 73, 78, 88, 81, 100, 104, 119, 102, 80, 82, 114, 75, 106, 82, 97, 86, 67, 49, 51,
    105, 70, 76, 85, 112, 54, 76, 99, 88, 56, 109, 50, 115, 10, 65, 107, 52, 82, 113, 72, 52,
    84, 116, 86, 66, 66, 73, 117, 82, 99, 56, 90, 89, 120, 107, 98, 51, 115, 111, 105, 54, 104,
    89, 73, 68, 109, 118, 74, 55, 121, 79, 98, 98, 116, 50, 73, 102, 117, 50, 88, 87, 53, 65, 107,
    69, 65, 43, 118, 90, 55, 121, 119, 102, 90, 80, 110, 122, 54, 10, 47, 80, 67, 43, 102, 99, 102,
    67, 70, 112, 81, 43, 88, 53, 48, 116, 70, 83, 66, 65, 101, 50, 110, 57, 70, 65, 66, 85, 107,
    103, 90, 79, 76, 51, 117, 76, 104, 111, 98, 107, 116, 57, 121, 89, 97, 51, 43, 90, 86, 79, 50,
    71, 112, 116, 55, 113, 43, 97, 47, 120, 69, 115, 122, 79, 10, 108, 73, 110, 65, 109, 43, 48, 83,
    72, 119, 74, 66, 65, 77, 74, 109, 43, 66, 57, 73, 65, 115, 106, 86, 78, 97, 100, 79, 90, 74, 76,
    55, 69, 66, 105, 119, 90, 86, 48, 121, 116, 89, 116, 70, 101, 120, 75, 111, 97, 79, 48, 76, 65, 65,
    101, 51, 110, 113, 89, 111, 54, 100, 98, 88, 10, 104, 57, 85, 43, 65, 67, 115, 69, 97, 52, 65, 48,
    111, 75, 108, 115, 69, 55, 54, 110, 73, 68, 105, 65, 106, 117, 107, 51, 98, 103, 80, 73, 120, 115,
    48, 67, 81, 66, 83, 72, 98, 121, 55, 51, 107, 71, 84, 86, 77, 109, 55, 89, 102, 113, 121, 112, 86,
    52, 52, 106, 83, 69, 114, 110, 10, 47, 53, 85, 88, 48, 48, 54, 70, 75, 65, 101, 110, 48, 48, 77, 121,
    115, 116, 105, 100, 103, 90, 100, 97, 108, 52, 69, 87, 48, 88, 48, 82, 114, 103, 104, 78, 101, 100,
    78, 83, 114, 117, 81, 72, 54, 87, 43, 66, 81, 51, 68, 82, 74, 43, 108, 90, 90, 106, 56, 67, 81, 67,
    117, 68, 10, 47, 82, 113, 84, 100, 102, 119, 97, 114, 99, 51, 114, 111, 70, 117, 43, 85, 49, 89, 84,
    100, 106, 48, 115, 99, 114, 76, 103, 78, 76, 74, 121, 102, 68, 112, 68, 99, 104, 104, 73, 73, 47, 48,
    120, 118, 49, 90, 87, 72, 74, 80, 66, 77, 121, 120, 116, 54, 116, 112, 104, 55, 87, 121, 47, 10, 81,
    112, 81, 48, 117, 79, 79, 115, 56, 49, 67, 70, 70, 100, 49, 71, 47, 105, 107, 67, 81, 65, 86, 121, 55,
    87, 122, 81, 109, 116, 100, 72, 69, 107, 107, 107, 101, 82, 100, 111, 99, 99, 105, 47, 115, 87,
    111, 73, 111, 108, 43, 76, 75, 87, 120, 122, 47, 88, 88, 49, 110, 106, 74, 104, 10, 56, 85, 115,
    50, 105, 47, 111, 83, 121, 99, 120, 111, 90, 122, 110, 108, 84, 121, 110, 43, 55, 87, 43, 113, 114,
    55, 114, 84, 97, 119, 75, 116, 113, 49, 122, 114, 65, 56, 112, 109, 84, 110, 85, 61, 10, 77, 254, 57,
    3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3,
    254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254,
    57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 254, 57, 3, 194, 57, 3,
    18, 177, 9, 8, 69, 78, 68, 82, 201, 9];

    let max_output_len = snap::decompress_len(&input).unwrap();
    let mut output = vec![0u8; max_output_len];

    println!("Input Len: {:?}", input.len());
    println!("Output Max Len: {:?}", max_output_len);

    let size = decompress(&input, &mut output).unwrap();
    println!("{}", str::from_utf8(&output[..size]).unwrap());
    println!("Output Len: {:?}", size);
}


fn main() {
    test_snap_comress();
    test_snap_decompress();
}