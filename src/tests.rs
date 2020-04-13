#[test]
fn it_works() {
    assert_eq!(2 + 2, 4);
}

#[test]
fn test_sm3() {
	use crate::sm3;
	use std::convert::TryInto;

	let message: [u8; 3] = "abc".as_bytes().try_into().expect("error");
	let digest: [u8; 32] = [
		0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
	];

	let result: [u8; 32] = sm3::SM3Calc(&message, message.len());
	println!("result = {:?}", result);
	assert_eq!(result, digest, "sm3 encrypt failed");
}

#[test]
fn test_sm4() {
	use crate::sm4;
    use std::convert::TryInto;

	let key :&[u8; 16] = "1234567890abcdef".as_bytes().try_into().expect("size of key slice is invalid");
    println!("key = {:?}", key);
	let data : [u8; 16] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

	println!("data = {:?}", data);
	let mut c: sm4::Sm4Cipher  = match sm4::Sm4Cipher::new(key){
        Ok(c)=> c,
        Err(e)=> panic!(e),
    };

    let d0 = c.encrypt(&data);
    
	println!("d0 = {:?}", &d0);
	//let mut d1 :[u8;16] = [0x0; 16];
	let d1 = c.decrypt(&d0);
	println!("d1 = {:?}", d1);
	assert_eq!(data, d1, "sm4 decrypt failed");
}
