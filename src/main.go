package main

import "fmt"

func main() {
	tag := NewRFIDTAG()                       // 实例化一个RFIDTAG对象
	fmt.Println("Card Number:", tag.CardNo()) // 打印卡号
	tag.memo[15][3][6] = 0b00000001
	tag.memo[15][3][7] = 0b00100000
	tag.memo[15][3][8] = 0b00110011

	// 设置sector15 block3 密钥A
	for i := 0; i < 6; i++ {
		tag.memo[15][3][i] = 0xFF
		tag.memo[15][3][i+10] = 0xFF
	}

	data := [16]byte{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'}
	password := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	// 使用正确的密码访问具有正确权限的扇块
	bo := tag.Write(15, 0, password, data)
	if bo {
		output := tag.Read(15, 0, password)
		fmt.Println(string(output[:]))
		fmt.Println("test1：正确访问测试成功")
	}

	//使用错误的密码访问具有正确权限的扇块
	password = [6]byte{0xF, 0xF, 0xF, 0xF, 0xF, 0xF}
	bo = tag.Write(15, 0, password, data)
	if !bo {
		fmt.Println("test2：密码错误测试成功")
	}

	password = [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	// 使用正确的密码访问不具有正确权限的扇块
	bo = tag.Write(15, 1, password, data)
	if !bo {
		fmt.Println("test3：权限错误测试成功")
	}
}
