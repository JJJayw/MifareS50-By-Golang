package main

import (
	"crypto/rand"
	"fmt"
	"io"
)

// NewUUID 生成全球唯一的ID
func NewUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// PatternBit 比较指定字节的权限位
func PatternBit(block int, access, authBit byte) bool {
	var mask byte
	var ab byte

	//将二进制位左移指定位数
	ab = authBit << block
	mask = 0b00010001 << block

	if access&mask == ab {
		return true
	}
	return false
}

// AuthThreeByte 向上封装PatternBit函数
func AuthThreeByte(block int, accessByte []byte, authByteA, authByteB, authByteC byte) bool {
	return PatternBit(block, accessByte[0], authByteA) && PatternBit(block, accessByte[1], authByteB) && PatternBit(block, accessByte[2], authByteC)
}
