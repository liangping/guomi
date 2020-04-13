// sm3

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_assignments)]
#![allow(unused_comparisons)]

const SM3_HASH_SIZE: usize = 32;

macro_rules! LeftRotate {
	($word:expr, $bits:expr) => {
		( ($word) << (($bits) % 32) | ($word) >> (32 - (($bits) % 32)) )
	};
}

struct SM3Context {
	digest: [u32; 8],
	block: [u8; 64],
}


fn SM3Init(context: &mut SM3Context) {
	context.digest[0] = 0x7380166F;
	context.digest[1] = 0x4914B2B9;
	context.digest[2] = 0x172442D7;
	context.digest[3] = 0xDA8A0600;
	context.digest[4] = 0xA96F30BC;
	context.digest[5] = 0x163138AA;
	context.digest[6] = 0xE38DEE4D;
	context.digest[7] = 0xB0FB0E4E;
}

fn SM3ProcessMessageBlock(context: &mut SM3Context) {
	let mut W: [u32; 68] = [0; 68];
	let mut W_: [u32; 64]= [0; 64];
	let (mut A, mut B, mut C, mut D, mut E, mut F, mut G, mut H): (u32, u32, u32, u32, u32, u32, u32, u32);
 	let (mut SS1, mut SS2, mut TT1, mut TT2): (u32, u32, u32, u32);

	/* 消息扩展 */
	for i in 0..16 {
		W[i] = to_u32(&(context.block[i * 4 .. (i + 1) * 4]));
		if IsLittleEndian() {
			W[i] = reverse_u32(W[i]);
		}
	}
	for i in 16..68 {
		W[i] = P1(W[i - 16] ^ W[i - 9] ^ LeftRotate!(W[i - 3], 15))
			^ LeftRotate!(W[i - 13], 7)	^ W[i - 6];
	}
	for i in 0..64 {
		W_[i] = W[i] ^ W[i + 4];
	}

 
	/* 消息压缩 */
	A = context.digest[0];
	B = context.digest[1];
	C = context.digest[2];
	D = context.digest[3];
	E = context.digest[4];
	F = context.digest[5];
	G = context.digest[6];
	H = context.digest[7];
	for i in 0..64 {
		SS1 = calc_ss1(A, E, i);
		SS2 = SS1 ^ LeftRotate!(A, 12);
		TT1 = wrapping_add_4p(FF(A, B, C, i), D, SS2, W_[i as usize]);
		TT2 = wrapping_add_4p(GG(E, F, G, i), H, SS1, W[i as usize]);
		D = C;
		C = LeftRotate!(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = LeftRotate!(F, 19);
		F = E;
		E = P0(TT2);
	}
	context.digest[0] ^= A;
	context.digest[1] ^= B;
	context.digest[2] ^= C;
	context.digest[3] ^= D;
	context.digest[4] ^= E;
	context.digest[5] ^= F;
	context.digest[6] ^= G;
	context.digest[7] ^= H;
}

pub fn SM3Calc(msg: &[u8], msgLen: usize) -> [u8; SM3_HASH_SIZE] {
	let mut context: SM3Context = SM3Context {
		digest: [0u32; 8],
		block: [0u8; 64],
	};
	let (i, mut remainder, mut bitLen): (usize, usize, u32) = (0, 0, 0);
 
	/* 初始化上下文 */
	SM3Init(&mut context);
 
	/* 对前面的消息分组进行处理 */
	for i in 0..msgLen / 64 {
		context.block.clone_from_slice(&msg[i * 64 .. (i + 1) * 64]);
		SM3ProcessMessageBlock(&mut context);
	}
 
	/* 填充消息分组，并处理 */
	bitLen = (msgLen * 8) as u32;
	if IsLittleEndian() {
		bitLen = reverse_u32(bitLen);
	}

	remainder = msgLen % 64;
	memcpy_array(&mut context.block, 0, &msg[i * 64 .. i * 64 + remainder], remainder);
	context.block[remainder] = 0x80;

	if remainder <= 55 {
		/* 长度按照大端法占8个字节，该程序只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset_array(&mut context.block, remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
		memcpy_array(&mut context.block, 64 - 4, &to_u8_array(bitLen), 4);
		SM3ProcessMessageBlock(&mut context);
	}
	else {
		memset_array(&mut context.block, remainder + 1, 0, 64 - remainder - 1);
		SM3ProcessMessageBlock(&mut context);

		/* 长度按照大端法占8个字节，该程序只考虑长度在 2**32 - 1（单位：比特）以内的情况，
		* 故将高 4 个字节赋为 0 。*/
		memset_array(&mut context.block, 0, 0, 64 - 4);
		memcpy_array(&mut context.block, 64 - 4, &to_u8_array(bitLen), 4);
		SM3ProcessMessageBlock(&mut context);
	}
 
	/* 返回结果 */
	if IsLittleEndian() {
		for i in 0..8 {
			context.digest[i] = reverse_u32(context.digest[i]);
		}
	}

	// print_context(&context);
	let mut result: [u8;SM3_HASH_SIZE] = [0;SM3_HASH_SIZE];
	memcpy_result(&mut result, &(context.digest));
	return result;
}



/** 以下为辅助函数 */
use std::mem;

// 判断运行环境是否小端
fn IsLittleEndian() -> bool {
	let d1: i32 = 1;
	let d2: [i8; 4] = unsafe{ mem::transmute::<i32, [i8; 4]>(d1) };
	d1 == d2[0] as i32
}

// 逆序排列数组，会修改原数组
fn reverse_array(array: &mut [u8; 4]) {
	let mut temp: u8;
	temp = array[0];
	array[0] = array[3];
	array[3] = temp;
	temp = array[1];
	array[1] = array[2];
	array[2] = temp;
}

// 逆序排列u32四个字节的存储顺序，返回新的u32变量，不改变原数据
fn reverse_u32(d: u32) -> u32 {
	let mut array: [u8; 4] = to_u8_array(d);
	reverse_array(&mut array);
	to_u32(&array)
}

// 4个字节的u8数组，转换为u32类型整数
fn to_u32(d: &[u8]) -> u32 {
	let ptr: *const u8 = d.as_ptr();
	let ptr: *const u32 = ptr as *const u32;
	let ret = unsafe{*ptr};
	ret
}

// u32类型整数，转换为4个字节的u8数组
fn to_u8_array(d: u32) -> [u8; 4] {
	let ret = unsafe{ mem::transmute::<u32, [u8; 4]>(d) };
	ret
}

// 安全加法，兼容整数溢出情况
fn wrapping_add_3p(d1: u32, d2: u32, d3: u32) -> u32 {
	d1.wrapping_add(d2).wrapping_add(d3)
}

fn wrapping_add_4p(d1: u32, d2: u32, d3: u32, d4: u32) -> u32 {
	d1.wrapping_add(d2).wrapping_add(d3).wrapping_add(d4)
}

fn calc_ss1(A: u32, E: u32, i: u8) -> u32 {
	if i == 0 || i == 32 {
		LeftRotate!(wrapping_add_3p(LeftRotate!(A, 12), E, T(i)), 7)
	} else {
		LeftRotate!(wrapping_add_3p(LeftRotate!(A, 12), E, LeftRotate!(T(i), i)), 7)
	}
}

fn T(i: u8) -> u32 {
	if i >= 0 && i <= 15 {
		return 0x79CC4519
	}
	else if i >= 16 && i <= 63 {
		return 0x7A879D8A
	}
	else {
		return 0
	}
}

fn FF(X: u32, Y: u32, Z: u32, i: u8) -> u32 {
	if i >= 0 && i <= 15 {
		return X ^ Y ^ Z
	}
	else if i >= 16 && i <= 63 {
		return (X & Y) | (X & Z) | (Y & Z)
	}
	else {
		return 0
	}
}
 
fn GG(X: u32, Y: u32, Z: u32, i: u8) -> u32 {
	if i >= 0 && i <= 15 {
		return X ^ Y ^ Z
	}
	else if i >= 16 && i <= 63 {
		return (X & Y) | (!X & Z)
	}
	else {
		return 0
	}
}

fn P0(X: u32) -> u32 {
	X ^ LeftRotate!(X, 9) ^ LeftRotate!(X, 17)
}

fn P1(X: u32) -> u32 {
	X ^ LeftRotate!(X, 15) ^ LeftRotate!(X, 23)
}


// 批量设置数组数值
fn memset_array(array: &mut [u8], start: usize, val: u8, n: usize) {
	for i in 0..n {
		array[start + i] = val;
	}
}

// 批量复制数组数据
fn memcpy_array(array: &mut [u8], start: usize, val: &[u8], n: usize) {
	for i in 0..n {
		array[start + i] = val[i];
	}
}

// 复制返回值
fn memcpy_result(result: &mut [u8], digest: &[u32;8]) {
	for i in 0..8 {
		let d: u32 = digest[i];
		let array: [u8;4] = to_u8_array(d);
		memcpy_array(result, i * 4, &array, 4);
	}
}

// 调试用打印函数
fn print_context(context: &SM3Context) {
	println!("===block===");
	for i in 0..16 {
		println!("{:?} {:?} {:?} {:?}", context.block[i * 4], context.block[i * 4 + 1],
			context.block[i * 4 + 2], context.block[i * 4 + 3]);
	}
	println!("===digest===");
	println!("{:?}", context.digest);
}