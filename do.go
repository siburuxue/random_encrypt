package random_encrypt

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/forgoer/openssl"
	"math"
	"strconv"
	"strings"
	"time"
)

type RandomEncrypt struct {
	// 北京时间时区信息
	timezoneOffset int64

	// key有效期（单位秒）
	timeInterval int64

	//options int32

	// 加密key长度
	keyLength int

	// 如果跨时区 冗余几秒
	secondRedundancy int64

	// 当前（北京/东八区时间）时间戳
	timestamp int64

	keyMap map[string]string

	// 加密算法
	cipherAlgo [6]string

	// 自定义盐值
	salt string
}

func (e *RandomEncrypt) Encrypt(str string) string {
	passphrase, iv := e.key(0)
	//fmt.Println(passphrase, iv)
	s, err := openssl.AesCBCEncrypt([]byte(str), []byte(passphrase), []byte(iv), openssl.PKCS7_PADDING)
	if err != nil {
		panic(e)
	}
	return base64.StdEncoding.EncodeToString(s)
}

func (e *RandomEncrypt) Decrypt(str string) string {
	current := e.getTimestamp()
	s, err := e.doDecrypt(str, 0)
	if err != nil {
		// 解决跨时区问题
		if e.isReEncrypt(current) {
			s, err = e.doDecrypt(str, current-e.timeInterval)
			if err != nil {
				panic(err)
			}
		}
	}
	return s
}

// SetSalt 自定义盐值 加密时不能为空
func (e *RandomEncrypt) SetSalt(salt string) *RandomEncrypt {
	e.salt = salt
	return e
}

// SetTimezoneOffset 自定义对齐时区 默认东八区
func (e *RandomEncrypt) SetTimezoneOffset(offset int64) *RandomEncrypt {
	e.timezoneOffset = offset
	return e
}

// SetTimeInterval 自定义加密key有效时间 默认5秒
func (e *RandomEncrypt) SetTimeInterval(timeInterval int64) *RandomEncrypt {
	e.timeInterval = timeInterval
	return e
}

// SetSecondRedundancy 自定义跨区间 冗余秒数 默认2秒
func (e *RandomEncrypt) SetSecondRedundancy(secondRedundancy int64) *RandomEncrypt {
	e.secondRedundancy = secondRedundancy
	return e
}

// Config 自定义设置参数 map[string]interface{}{"salt": "salt", "offset": 10, "timeInterval": 7, "secondRedundancy": 3}
func (e *RandomEncrypt) Config(config map[string]interface{}) *RandomEncrypt {
	_, ok := config["salt"]
	if ok {
		e.SetSalt(fmt.Sprintf("%v", config["salt"]))
	}
	_, ok = config["offset"]
	if ok {
		e.SetTimezoneOffset(int64(config["offset"].(int)))
	}
	_, ok = config["timeInterval"]
	if ok {
		e.SetTimeInterval(int64(config["timeInterval"].(int)))
	}
	_, ok = config["secondRedundancy"]
	if ok {
		e.SetSecondRedundancy(int64(config["secondRedundancy"].(int)))
	}
	return e
}

func NewRandomEncrypt() RandomEncrypt {
	e := RandomEncrypt{
		timezoneOffset:   8,
		timeInterval:     5,
		keyLength:        16,
		secondRedundancy: 2,
		timestamp:        0,
		salt:             "",
		keyMap: map[string]string{
			"1": "#",
			"2": "0",
			"3": "*",
			"4": "9",
			"5": "8",
			"6": "7",
			"7": "6",
			"8": "5",
			"9": "4",
			"*": "3",
			"0": "2",
			"#": "1",
		},
		cipherAlgo: [6]string{
			"AES-128-CBC",
			"ARIA-128-CTR",
			"CAMELLIA-128-CBC",
			"SEED-CBC",
			"SM4-CBC",
			"AES-256-CBC-HMAC-SHA256",
		},
	}
	return e
}

// 判断是否需要再次解密
func (e *RandomEncrypt) isReEncrypt(current int64) bool {
	return current%e.timeInterval <= e.secondRedundancy
}
func (e *RandomEncrypt) doDecrypt(str string, timestamp int64) (string, error) {
	passphrase, iv := e.key(timestamp)
	dst, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		panic(err)
	}
	s, err := openssl.AesCBCDecrypt(dst, []byte(passphrase), []byte(iv), openssl.PKCS7_PADDING)
	return string(s), err
}

// 获取加密方式
func (e *RandomEncrypt) getCipherAlgo() string {
	return e.cipherAlgo[0]
}

// 获取当前时间戳
func (e *RandomEncrypt) getTimestamp() int64 {
	return time.Now().Unix()
}

func (e *RandomEncrypt) getTimeGroup(timestamp int64) int64 {
	return int64(math.Ceil(float64(timestamp)/float64(e.timeInterval))) * e.timeInterval
}

func (e *RandomEncrypt) formatDatetime(timestamp int64) string {
	_, offset := time.Now().Zone()
	offset /= 3600
	seconds := (e.timezoneOffset - int64(offset)) * 3600
	timestamp += seconds
	return time.Unix(timestamp, 0).Format("20060102150405")
}

func (e *RandomEncrypt) getEncryptKey(key string, index int) string {
	d := []byte(key + e.salt)
	m := md5.New()
	m.Write(d)
	key = strings.ToLower(hex.EncodeToString(m.Sum(nil)))
	return key[index : index+e.keyLength]
}

func (e *RandomEncrypt) key(timestamp int64) (string, string) {
	if timestamp == 0 {
		timestamp = e.getTimestamp()
	}
	e.timestamp = timestamp
	timestamp = e.getTimeGroup(timestamp)
	datetime := e.formatDatetime(timestamp)
	datetimeArr := strings.Split(datetime, "")
	for i, s := range datetimeArr {
		datetimeArr[i] = e.keyMap[s]
	}
	key := strings.Join(datetimeArr, "")
	datetimeInt, _ := strconv.Atoi(datetime)
	index := datetimeInt % e.keyLength
	passphrase := datetime + key + datetime
	iv := key + datetime + key
	return e.getEncryptKey(passphrase, index), e.getEncryptKey(iv, index)
}
