package main

import (
	"log"
)

type RFIDTAG struct {
	cardNo string          //卡号
	memo   [16][4][16]byte // 控制块3，密钥A 0~5字节，密钥B 10~15字节
}

func NewRFIDTAG() *RFIDTAG {
	no, err := NewUUID()
	if err != nil {
		log.Printf("Error %v", err)
	}
	return &RFIDTAG{cardNo: no, memo: [16][4][16]byte{}}
}

func (r *RFIDTAG) CardNo() string {
	return r.cardNo
}

// AuthA 密码验证
func (r *RFIDTAG) AuthA(sector int, password [6]byte) bool {
	var sign bool
	// 校验密钥A
	for i := 0; i < 6; i++ {
		if r.memo[sector][3][i] != password[i] {
			sign = false
			break
		}
		sign = true
	}
	return sign
}

func (r *RFIDTAG) AuthB(sector int, password [6]byte) bool {
	var sign bool
	// 校验密钥A
	for i := 0; i < 6; i++ {
		if r.memo[sector][3][i+10] != password[i] {
			sign = false
			break
		}
		sign = true
	}
	return sign
}

func (r *RFIDTAG) Access(sector, block int, password [6]byte, control int) bool { //访问权限
	accessByte := r.memo[sector][3]

	// control Read:0; Write:1; increase:2; Decrease:3
	// 根据权限位给予相应的操作权限
	if AuthThreeByte(block, accessByte[6:9], 0b00010001, 0b00000001, 0b00000000) {
		// 权限位 000
		switch control {
		case 0, 1, 2, 3:
			return r.AuthA(sector, password) && r.AuthB(sector, password)
		}
	} else if AuthThreeByte(block, accessByte[6:9], 0b00000001, 0b00000001, 0b00000001) {
		// 权限位 010
		switch control {
		case 0:
			return r.AuthA(sector, password) && r.AuthB(sector, password)
		default:
			return false
		}
	} else if AuthThreeByte(block, accessByte[6:9], 0b00010000, 0b00010001, 0b00000000) {
		// 权限位 100
		switch control {
		case 0:
			return r.AuthA(sector, password) && r.AuthB(sector, password)
		case 1:
			return r.AuthB(sector, password)
		default:
			return false
		}
	} else if AuthThreeByte(block, accessByte[6:9], 0b00000000, 0b00010001, 0b00000001) {
		// 权限位 110
		switch control {
		case 0:
			return r.AuthA(sector, password) && r.AuthB(sector, password)
		case 1:
			return r.AuthB(sector, password)
		case 2:
			return r.AuthB(sector, password)
		case 3:
			return r.AuthA(sector, password) && r.AuthB(sector, password)
		}
	} else if AuthThreeByte(block, accessByte[6:9], 0b00010001, 0b00000000, 0b00010000) {
		// 权限位 001
		switch control {
		case 0:
			return r.AuthA(sector, password) && r.AuthB(sector, password)
		case 3:
			return r.AuthA(sector, password) && r.AuthB(sector, password)
		default:
			return false
		}
	} else if AuthThreeByte(block, accessByte[6:9], 0b00000001, 0b00000000, 0b00010001) {
		// 权限位 011
		switch control {
		case 0:
			return r.AuthB(sector, password)
		case 1:
			return r.AuthB(sector, password)
		default:
			return false
		}
	} else if AuthThreeByte(block, accessByte[6:9], 0b00010000, 0b00010000, 0b00010001) {
		// 权限位 101
		switch control {
		case 0:
			return r.AuthB(sector, password)
		default:
			return false
		}
	} else if AuthThreeByte(block, accessByte[6:9], 0b00000000, 0b00010000, 0b00010001) {
		// 权限位 111
		switch control {
		default:
			return false

		}
	}
	return false
}

func (r *RFIDTAG) Read(sector, block int, password [6]byte) [16]byte { //读数据
	if r.Access(sector, block, password, 0) {
		return r.memo[sector][block]
	}
	return [16]byte{}
}

func (r *RFIDTAG) Write(sector, block int, password [6]byte, data [16]byte) bool { //写数据
	if r.Access(sector, block, password, 1) {
		r.memo[sector][block] = data
		return true
	}
	return false
}
