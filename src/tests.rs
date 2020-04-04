#[cfg(test)]
use crate::sm4;

#[test]
fn it_works() {
    assert_eq!(2 + 2, 4);
}

#[test]
fn test_sm4() {

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
