#!/usr/bin/python

import subprocess
import re

ff1 = [
    # AES-128
   [
   	10,
   	"2B7E151628AED2A6ABF7158809CF4F3C",
   	"",
   	"0123456789",
   	"2433477484",
   ],
   [
   	10,
   	"2B7E151628AED2A6ABF7158809CF4F3C",
   	"39383736353433323130",
   	"0123456789",
   	"6124200773",
   ],
   [
   	36,
   	"2B7E151628AED2A6ABF7158809CF4F3C",
   	"3737373770717273373737",
   	"0123456789abcdefghi",
   	"a9tv40mll9kdu509eum",
   ],
   
   # AES-192
   [
   	10,
   	"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
   	"",
   	"0123456789",
   	"2830668132",
   ],
   [
   	10,
   	"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
   	"39383736353433323130",
   	"0123456789",
   	"2496655549",
   ],
   [
   	36,
   	"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
   	"3737373770717273373737",
   	"0123456789abcdefghi",
   	"xbj3kv35jrawxv32ysr",
   ],
   
   # AES-256
   [
   	10,
   	"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
   	"",
   	"0123456789",
   	"6657667009",
   ],
   [
   	10,
   	"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
   	"39383736353433323130",
   	"0123456789",
   	"1001623463",
   ],
   [
   	36,
   	"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
   	"3737373770717273373737",
   	"0123456789abcdefghi",
   	"xs8a0azh2avyalyzuwd",
   ],
]

ff3 = [
    # AES-128
    [
    	10,
    	"EF4359D8D580AA4F7F036D6F04FC6A94",
    	"D8E7920AFA330A73",
    	"890121234567890000",
    	"750918814058654607",
    ],
    [
    	10,
    	"EF4359D8D580AA4F7F036D6F04FC6A94",
    	"9A768A92F60E12D8",
    	"890121234567890000",
    	"018989839189395384",
    ],
    [
    	10,
    	"EF4359D8D580AA4F7F036D6F04FC6A94",
    	"D8E7920AFA330A73",
    	"89012123456789000000789000000",
    	"48598367162252569629397416226",
    ],
    [
    	10, "EF4359D8D580AA4F7F036D6F04FC6A94",
    	"0000000000000000",
    	"89012123456789000000789000000",
    	"34695224821734535122613701434",
    ],
    [
    	26, "EF4359D8D580AA4F7F036D6F04FC6A94",
    	"9A768A92F60E12D8",
    	"0123456789abcdefghi",
    	"g2pk40i992fn20cjakb",
    ],
    
    # AES-192
    [
    	10,
    	"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
    	"D8E7920AFA330A73",
    	"890121234567890000",
    	"646965393875028755",
    ],
    [
    	10,
    	"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
    	"9A768A92F60E12D8",
    	"890121234567890000",
    	"961610514491424446",
    ],
    [
    	10,
    	"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
    	"D8E7920AFA330A73",
    	"89012123456789000000789000000",
    	"53048884065350204541786380807",
    ],
    [
    	10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
    	"0000000000000000",
    	"89012123456789000000789000000",
    	"98083802678820389295041483512",
    ],
    [
    	26, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
    	"9A768A92F60E12D8",
    	"0123456789abcdefghi",
    	"i0ihe2jfj7a9opf9p88",
    ],
    
    # AES-256
    [
    	10,
    	"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
    	"D8E7920AFA330A73",
    	"890121234567890000",
    	"922011205562777495",
    ],
    [
    	10,
    	"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
    	"9A768A92F60E12D8",
    	"890121234567890000",
    	"504149865578056140",
    ],
    [
    	10,
    	"EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
    	"D8E7920AFA330A73",
    	"89012123456789000000789000000",
    	"04344343235792599165734622699",
    ],
    [
    	10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
    	"0000000000000000",
    	"89012123456789000000789000000",
    	"30859239999374053872365555822",
    ],
    [
    	26, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
    	"9A768A92F60E12D8",
    	"0123456789abcdefghi",
    	"p0b2godfja9bhb7bk38",
    ],
]

def main():
    regexp = re.compile('(?<=ciphertext: ).+')
    
    countErr = 0
    
    print('FF1 test: ')
    for index, test in enumerate(ff1):
        radix = test[0]
        key = test[1]
        tweak = test[2]
        plain = test[3]
        cipher = test[4]
        p = subprocess.Popen(['./example', key, tweak, str(radix), plain], stdin = subprocess.PIPE, stdout = subprocess.PIPE)
        output = p.communicate()[0]
        results = regexp.findall(output.decode('utf-8'))[0]
        p.wait()
    
        print('case #%d:' % index)
        print('plaintext: ' + plain)
        print('ciphertext: ' + results)
        if results != cipher:
            print('Wrong!')
            ++countErr
        else:
            print('Right!')
    
    print('-------------------------\nFF3 test: ')
    for index, test in enumerate(ff3):
        radix = test[0]
        key = test[1]
        tweak = test[2]
        plain = test[3]
        cipher = test[4]
        p = subprocess.Popen(['./example', key, tweak, str(radix), plain], stdin = subprocess.PIPE, stdout = subprocess.PIPE)
        output = p.communicate()[0]
        results = regexp.findall(output.decode('utf-8'))[1]
        p.wait()
    
        print('case #%d:' % index)
        print('plaintext: ' + plain)
        print('ciphertext: ' + results)
        if results != cipher:
            print('Wrong!')
            ++countErr
        else:
            print('Right!')
    
    print('Finish! %d error!' % countErr)

if __name__ == '__main__':
    main()

